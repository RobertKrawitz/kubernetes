// +build linux

/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package quota

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"golang.org/x/sys/unix"
	"sync"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/util/mount"
)

// Need both so we can find the quota for a given directory and
// see whether a given quota is in use.
var dirQuotaMap = make(map[string]QuotaID)
var quotaDirMap = make(map[QuotaID]string)
var quotaLock sync.RWMutex

var mountpointsMap = make(map[string]string)
var mountpointLock sync.RWMutex

var supportsQuotas = make(map[string]bool)
var supportsQuotasLock sync.RWMutex

var quotaCmd string
var quotaCmdInitialized bool
var quotaCmdLock sync.RWMutex

var quotaCmds = []string{"/sbin/xfs_quota",
	"/usr/sbin/xfs_quota",
	"/bin/xfs_quota"}

const (
	linuxXfsMagic = 0x58465342
	// XXXXXXX Need a better way of doing this...
	firstQuota QuotaID = 1048577
)

func detectMountpoint(m mount.Interface, path string) (string, error) {
	xpath, err := filepath.Abs(path)
	if err != nil {
		return "/", err
	}
	xpath, err = filepath.EvalSymlinks(xpath)
	if err != nil {
		return "/", err
	}
	for xpath != "" {
		isNotMount, err := m.IsNotMountPoint(xpath)
		if err != nil {
			return "/", err
		}
		if !isNotMount {
			glog.V(3).Infof("getMountpoint %s found! %s", path, xpath)
			mountpointsMap[path] = xpath
			return xpath, nil
		}
		xpath = filepath.Dir(xpath)
	}
	return "/", nil
}	

// getMountpoint returns the mount point for the specified path
func getMountpoint(m mount.Interface, path string) (string, error) {
	mountpointLock.Lock()
	defer mountpointLock.Unlock()
	if mountpoint, ok := mountpointsMap[path]; ok {
		return mountpoint, nil
	}
	mountpoint, err := detectMountpoint(m, path)
	mountpointsMap[path] = mountpoint
	return mountpoint, err
}

func getXFSQuotaCmd() (string, error) {
	quotaCmdLock.Lock()
	defer quotaCmdLock.Unlock()
	if (quotaCmdInitialized) {
		return quotaCmd, nil
	}
	for _, program := range quotaCmds {
		fileinfo, err := os.Stat(program)
		if err == nil && ((fileinfo.Mode().Perm() & (1 << 6)) != 0) {
			glog.V(3).Infof("Found %s", program)
			quotaCmd = program
			quotaCmdInitialized = true
			return quotaCmd, nil
		}
	}
	glog.V(3).Infof("No xfs_quota program found")
	quotaCmdInitialized = true
	return "", fmt.Errorf("No xfs_quota program found")
}

func runXFSQuotaCommand(m mount.Interface, path string, command string) (*exec.Cmd, error) {
	quotaCmd, err := getXFSQuotaCmd()
	if err != nil {
		return nil, err
	}
	mountpoint, err := getMountpoint(m, path)
	if err != nil {
		return nil, err
	}
	glog.V(3).Infof("runXFSQuotaCommand %s -x %s -c %s", quotaCmd, mountpoint, command)
	cmd := exec.Command(quotaCmd, "-x", mountpoint, "-c", command)

	return cmd, nil
}

func detectSupportsQuotas(m mount.Interface, path string) (bool, error) {
	// For now, we're only going to do quotas on XFS
	glog.V(3).Infof("detectSupportQuota %s", path)
	buf := unix.Statfs_t{}
	if err := unix.Statfs(path, &buf); err != nil {
		return false, fmt.Errorf("statfs(%q): %v", path, err)
	}
	if (buf.Type != linuxXfsMagic) {
		return false, fmt.Errorf("runXFSQuotaCommand: %s not on XFS filesystem", path)
	}
	out, err := runXFSQuotaCommand(m, path, "print")
	if err != nil {
		glog.V(3).Infof("runXFSQuotaCommand failed %v", err)
		return false, err
	}
	data, err := out.CombinedOutput()
	
	if err != nil {
		return false, err
	}
	if strings.Contains(string(data), "pquota") {
		return true, nil
	}
	return false, nil
}

// Does the path support quotas
func SupportsQuotas(m mount.Interface, path string) (bool, error) {
	supportsQuotasLock.Lock()
	defer supportsQuotasLock.Unlock()
	if quotas, ok := supportsQuotas[path]; ok {
		return quotas, nil
	}
	quotas, err := detectSupportsQuotas(m, path)
	if err != nil {
		glog.V(3).Infof("SupportsQuotas failed %v", err)
	}
	supportsQuotas[path] = quotas
	return quotas, err
}

func setQuotaOn(m mount.Interface, path string, id QuotaID, bytes int64) error {
	glog.V(3).Infof("setQuotaOn %s ID %v bytes %v", path, id, bytes)
	cmd, err := runXFSQuotaCommand(m, path, fmt.Sprintf("limit -p bhard=%v %v", bytes, id))
	if err != nil {
		return err
	}
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	cmd, err = runXFSQuotaCommand(m, path, fmt.Sprintf("project -s -p %s %v", path, id))
	if err != nil {
		return err
	}
	_, err = cmd.CombinedOutput()
	return err
}

func AssignQuota(m mount.Interface, path string, bytes int64) (QuotaID, error) {
	ok, err := SupportsQuotas(m, path)
	if !ok {
		return 0, fmt.Errorf("Quotas not supported on %s: %v", path, err)
	}
	quotaLock.Lock()
	defer quotaLock.Unlock()
	_, ok = dirQuotaMap[path]
	if ok {
		return 0, fmt.Errorf("Quota already assigned to %s", path);
	}
	for id := firstQuota; id == id; id++ {
		_, ok := quotaDirMap[id]
		if ! ok {
			err := setQuotaOn(m, path, id, bytes)
			if err != nil {
				glog.V(3).Infof("Assign quota FAILED %v", err)
				return QuotaID(0), err
			}
			quotaDirMap[id] = path
			dirQuotaMap[path] = id
			return id, nil
		}
	}
	return QuotaID(0), fmt.Errorf("Unable to find a quota ID for %s", path)
}

func GetQuotaID(m mount.Interface, path string) (QuotaID, error) {
	quotaLock.Lock()
	defer quotaLock.Unlock()
	_, ok := dirQuotaMap[path]
	if !ok {
		return 0, fmt.Errorf("No quota available for %s", path);
	} else {
		return dirQuotaMap[path], nil
	}
}

func GetConsumption(m mount.Interface, path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	_, ok := dirQuotaMap[path]
	if !ok {
		return 0, fmt.Errorf("No quota available for %s", path);
	}
	ok, err := SupportsQuotas(m, path)
	if !ok {
		return 0, fmt.Errorf("Quotas not supported on %s: %v", path, err)
	}
	_, err = runXFSQuotaCommand(m, path, "quota -N -p 1 -b -n")
	if err != nil {
		return 0, err
	}
	// DO THE REAL WORK
	return 0, fmt.Errorf("not implemented")
}

func doClearQuota(m mount.Interface, path string) (error) {
	ok, err := SupportsQuotas(m, path)
	if !ok {
		return fmt.Errorf("Quotas not supported on %s: %v", path, err)
	}
	cmd, err := runXFSQuotaCommand(m, path, fmt.Sprintf("limit -p bhard=0 %v", dirQuotaMap[path]))
	err = cmd.Run()
	if !ok {
		glog.V(3).Infof("Unable to clear quota %v %s: %v", dirQuotaMap[path], path, err)
		return err
	}
	// If this fails, there is nothing anyone can do
	cmd, err = runXFSQuotaCommand(m, path, fmt.Sprintf("project -C -p %s %v", path, dirQuotaMap[path]))
	if !ok {
		glog.V(3).Infof("Unable to disassociate quota %v %s: %v", dirQuotaMap[path], path, err)
		return err
	}
	return nil
}

func ClearQuota(m mount.Interface, path string) (error) {
	glog.V(3).Infof("ClearQuota %s", path)
	quotaLock.Lock()
	defer quotaLock.Unlock()
	_, ok := dirQuotaMap[path]
	if !ok {
		return fmt.Errorf("ClearQuota: No quota available for %s", path)
	}
	err := doClearQuota(m, path)
	delete(quotaDirMap, dirQuotaMap[path])
	delete(dirQuotaMap, path)
	mountpointLock.Lock()
	delete(mountpointsMap, path)
	mountpointLock.Unlock()
	supportsQuotasLock.Lock()
	delete(supportsQuotas, path)
	supportsQuotasLock.Unlock()
	return err
}
