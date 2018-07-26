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
	"regexp"
	"strconv"

	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/util/mount"
)


// Pod -> ID
var podQuotaMap    = make(map[string]QuotaID)
// Dir -> ID (for convenience)
var dirQuotaMap    = make(map[string]QuotaID)
// ID -> pod
var quotaPodMap    = make(map[QuotaID]string)
// Directory -> pod
var dirPodMap      = make(map[string]string)
// Pod -> refcount
var podDirCountMap = make(map[string]int)
// ID -> size
var quotaSizeMap   = make(map[QuotaID]int64)
var quotaLock sync.RWMutex

// Directory -> mountpoint
var mountpointsMap = make(map[string]string)
var mountpointLock sync.RWMutex

var supportsQuotasMap = make(map[string]bool)
var supportsQuotasLock sync.RWMutex

var quotaCmd string
var quotaCmdInitialized bool
var quotaCmdLock sync.RWMutex

var quotaCmds = []string{"/sbin/xfs_quota",
	"/usr/sbin/xfs_quota",
	"/bin/xfs_quota"}

var quotaParseRegexp *regexp.Regexp = regexp.MustCompile("^[^ \t]*[ \t]*([123456789][0123456789]*)")

const (
	linuxXfsMagic = 0x58465342
	// XXXXXXX Need a better way of doing this...
	firstQuota QuotaID = 1048577
)

func detectMountpoint(m mount.Interface, path string) (error) {
	xpath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	xpath, err = filepath.EvalSymlinks(xpath)
	if err != nil {
		return err
	}
	for xpath != "" {
		isNotMount, err := m.IsNotMountPoint(xpath)
		if err != nil {
			return err
		}
		if !isNotMount {
			klog.V(3).Infof("getMountpoint %s found! %s", path, xpath)
			mountpointsMap[path] = xpath
			return nil
		}
		xpath = filepath.Dir(xpath)
	}
	return nil
}	

// getMountpoint returns the mount point for the specified path
func getMountpoint(path string) (string, error) {
	mountpointLock.Lock()
	defer mountpointLock.Unlock()
	if mountpoint, ok := mountpointsMap[path]; ok {
		return mountpoint, nil
	}
	return "/", fmt.Errorf("Mount point not found for %s", path);
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
			klog.V(3).Infof("Found %s", program)
			quotaCmd = program
			quotaCmdInitialized = true
			return quotaCmd, nil
		}
	}
	klog.V(3).Infof("No xfs_quota program found")
	quotaCmdInitialized = true
	return "", fmt.Errorf("No xfs_quota program found")
}

func runXFSQuotaCommand(path string, command string) (*exec.Cmd, error) {
	quotaCmd, err := getXFSQuotaCmd()
	if err != nil {
		return nil, err
	}
	mountpoint, err := getMountpoint(path)
	if err != nil {
		return nil, err
	}
	klog.V(3).Infof("runXFSQuotaCommand %s -x %s -c %s", quotaCmd, mountpoint, command)
	cmd := exec.Command(quotaCmd, "-x", mountpoint, "-c", command)

	return cmd, nil
}

func detectSupportsQuotas(path string) (bool, error) {
	// For now, we're only going to do quotas on XFS
	klog.V(3).Infof("detectSupportQuota %s", path)
	buf := unix.Statfs_t{}
	if err := unix.Statfs(path, &buf); err != nil {
		return false, fmt.Errorf("statfs(%q): %v", path, err)
	}
	if (buf.Type != linuxXfsMagic) {
		return false, fmt.Errorf("runXFSQuotaCommand: %s not on XFS filesystem", path)
	}
	out, err := runXFSQuotaCommand(path, "print")
	if err != nil {
		klog.V(3).Infof("runXFSQuotaCommand failed %v", err)
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
	if quotas, ok := supportsQuotasMap[path]; ok {
		return quotas, nil
	}
	detectMountpoint(m, path)
	quotas, err := detectSupportsQuotas(path)
	if err != nil {
		klog.V(3).Infof("SupportsQuotas failed %v", err)
	}
	supportsQuotasMap[path] = quotas
	return quotas, err
}

func setQuotaOn(path string, id QuotaID, bytes int64) error {
	klog.V(3).Infof("setQuotaOn %s ID %v bytes %v", path, id, bytes)
	cmd, err := runXFSQuotaCommand(path, fmt.Sprintf("limit -p bhard=%v %v", bytes, id))
	if err != nil {
		return err
	}
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}
	cmd, err = runXFSQuotaCommand(path, fmt.Sprintf("project -s -p %s %v", path, id))
	if err != nil {
		return err
	}
	_, err = cmd.CombinedOutput()
	return err
}

func AssignQuota(m mount.Interface, path string, poduid string, bytes int64) (QuotaID, error) {
	err := detectMountpoint(m, path)
	if err != nil {
		return BadQuota, fmt.Errorf("Cannot detect mountpoint for %s: %v", path, err)
	}
	ok, err := SupportsQuotas(m, path)
	if !ok {
		return BadQuota, fmt.Errorf("Quotas not supported on %s: %v", path, err)
	}
	quotaLock.Lock()
	defer quotaLock.Unlock()
	pod, ok := dirPodMap[path]
	if ok {
		if pod != poduid {
			return BadQuota, fmt.Errorf("Requesting quota on existing directory %s but different pod %s %s", path, pod, poduid)
		}
	}
	id, ok := podQuotaMap[poduid]
	if ok {
		if quotaSizeMap[id] != bytes {
			return BadQuota, fmt.Errorf("Requesting quota of different size: old %v new %v", quotaSizeMap[id], bytes)
		}
		err = setQuotaOn(path, id, bytes)
		if err != nil {
			return BadQuota, err
		} else {
			dirQuotaMap[path]   = id
			dirPodMap[path]     = poduid
			return id, nil
		}
	}
	for id := firstQuota; id == id; id++ {
		_, ok := quotaPodMap[id]
		if ! ok {
			err := setQuotaOn(path, id, bytes)
			if err != nil {
				klog.V(3).Infof("Assign quota FAILED %v", err)
				return QuotaID(0), err
			}
			quotaPodMap[id]     = poduid
			quotaSizeMap[id]    = bytes
			podQuotaMap[poduid] = id
			dirQuotaMap[path]   = id
			dirPodMap[path]     = poduid
			if count, ok := podDirCountMap[poduid]; ok {
				podDirCountMap[poduid] = count + 1
			} else {
				podDirCountMap[poduid] = 1
			}
			return id, nil
		}
	}
	return QuotaID(0), fmt.Errorf("Unable to find a quota ID for %s", path)
}

func GetQuotaID(path string) (QuotaID, error) {
	quotaLock.Lock()
	defer quotaLock.Unlock()
	id, ok := dirQuotaMap[path]
	if !ok {
		return BadQuota, fmt.Errorf("No quota available for %s", path);
	} else {
		return id, nil
	}
}

func internalGetConsumption(path string) (int64, error) {
	id, ok := dirQuotaMap[path]
	if !ok {
		return 0, fmt.Errorf("No quota available for %s", path);
	}
	out, err := runXFSQuotaCommand(path, fmt.Sprintf("quota -N -p %v -b -n", id))
	if err != nil {
		return 0, err
	}
	data, err := out.Output()
	if err != nil {
		return 0, err
	}
	match := quotaParseRegexp.FindStringSubmatch(string(data))
	if match == nil {
		return 0, fmt.Errorf("Unable to parse quota output")
	}
	size, err := strconv.ParseInt(match[1], 10, 64)
	if match == nil {
		return 0, fmt.Errorf("Unable to parse quota output")
	}
	return size, nil
}	

func GetConsumption(path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	size, error := internalGetConsumption(path)
	return size, error
}

func doClearQuota(path string, clearQuota bool) (error) {
	// Disassociate the directory from the quota
	cmd, err := runXFSQuotaCommand(path, fmt.Sprintf("project -C -p %s %v", path, dirQuotaMap[path]))
	err = cmd.Run()
	if err != nil {
		klog.V(3).Infof("Unable to disassociate quota %v %s: %v", dirQuotaMap[path], path, err)
		return err
	}

	// If the refcount is going to go to zero, clear the quota
	if clearQuota {
		cmd, err := runXFSQuotaCommand(path, fmt.Sprintf("limit -p bhard=0 %v", dirQuotaMap[path]))
		err = cmd.Run()
		if err != nil {
			klog.V(3).Infof("Unable to clear quota %v %s: %v", dirQuotaMap[path], path, err)
			return err
		}
	}
	return nil
}

func ClearQuota(path string) (error) {
	klog.V(3).Infof("ClearQuota %s", path)
	quotaLock.Lock()
	defer quotaLock.Unlock()
	poduid, ok := dirPodMap[path]
	if !ok {
		klog.V(3).Infof("ClearQuota: Cannot find pod for directory %s", path)
		return fmt.Errorf("ClearQuota: Cannot find pod for directory %s", path)
	}
	_, ok = podQuotaMap[poduid]
	if !ok {
		klog.V(3).Infof("ClearQuota: No quota available for %s", path)
		return fmt.Errorf("ClearQuota: No quota available for %s", path)
	}
	consumption, er := internalGetConsumption(path)
	klog.V(3).Infof("****** Before clearing quota consumption was %v (%v)", consumption, er)
	clearQuota := podDirCountMap[poduid] == 1
	err := doClearQuota(path, clearQuota)
	podDirCountMap[poduid]--
	delete(dirPodMap, path)
	delete(dirQuotaMap, path)
	if clearQuota {
		klog.V(3).Infof("Dir count for pod %s cleared", poduid)
		delete(quotaSizeMap, podQuotaMap[poduid])
		delete(quotaPodMap, podQuotaMap[poduid])
		delete(podDirCountMap, poduid)
		delete(podQuotaMap, poduid)
	} else {
		klog.V(3).Infof("Not clearing quota for pod %s; still %v dirs outstanding", poduid, podDirCountMap[poduid])
	}
	mountpointLock.Lock()
	delete(mountpointsMap, path)
	mountpointLock.Unlock()
	supportsQuotasLock.Lock()
	delete(supportsQuotasMap, path)
	supportsQuotasLock.Unlock()
	return err
}
