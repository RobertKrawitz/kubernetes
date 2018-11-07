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

package common

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/util/mount"
)

var quotaCmd string
var quotaCmdInitialized bool
var quotaCmdLock sync.RWMutex

var quotaCmds = []string{"/sbin/xfs_quota",
	"/usr/sbin/xfs_quota",
	"/bin/xfs_quota"}

var quotaParseRegexp = regexp.MustCompile("^[^ \t]*[ \t]*([0123456789][0123456789]*)")

var mountParseRegexp = regexp.MustCompilePOSIX("^([^ ]*)[ \t]*([^ ]*)[ \t]*([^ ]*)") // Ignore options etc.

var mountsFile = "/proc/self/mounts"

// DetectBackingDevInternal Separate the innards for ease of testing
func DetectBackingDevInternal(mountpoint string, mounts string) (string, error) {
	file, err := os.Open(mounts)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := mountParseRegexp.FindStringSubmatch(scanner.Text())
		if match != nil {
			device := match[1]
			mount := match[2]
			if mount == mountpoint {
				return device, nil
			}
		}
	}
	return "", fmt.Errorf("couldn't find backing device for %s", mountpoint)
}

// DetectBackingDev assumes that the mount point provided is valid
func DetectBackingDev(_ mount.Interface, mountpoint string) (string, error) {
	return DetectBackingDevInternal(mountpoint, mountsFile)
}

// DetectMountpointInternal assumes that the path has been fully canonicalized
// Breaking this up helps with testing
func DetectMountpointInternal(m mount.Interface, path string) (string, error) {
	for path != "" && path != "/" {
		// per pkg/util/mount/mount_linux this detects all but
		// a bind mount from one part of a mount to another.
		// For our purposes that's fine; we simply want the "true"
		// mount point
		//
		// IsNotMountPoint proved much more troublesome; it actually
		// scans the mounts, and when a lot of mount/unmount
		// activity takes place, it is not able to get a consistent
		// view of /proc/self/mounts, causing it to time out and
		// report incorrectly.
		isNotMount, err := m.IsLikelyNotMountPoint(path)
		if err != nil {
			return "/", err
		}
		if !isNotMount {
			return path, nil
		}
		path = filepath.Dir(path)
	}
	return "/", nil
}

// DetectMountpoint -- detect the mountpoint for a directory.
func DetectMountpoint(m mount.Interface, path string) (string, error) {
	xpath, err := filepath.Abs(path)
	if err == nil {
		if xpath, err = filepath.EvalSymlinks(xpath); err == nil {
			if xpath, err = DetectMountpointInternal(m, xpath); err == nil {
				return xpath, nil
			}
		}
	}
	return "/", err
}

func getXFSQuotaCmd() (string, error) {
	quotaCmdLock.Lock()
	defer quotaCmdLock.Unlock()
	if quotaCmdInitialized {
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

func runXFSQuotaCommand(mountpoint string, command string) (*exec.Cmd, error) {
	quotaCmd, err := getXFSQuotaCmd()
	if err != nil {
		return nil, err
	}
	klog.V(3).Infof("runXFSQuotaCommand %s -x -f %s -c %s", quotaCmd, mountpoint, command)
	cmd := exec.Command(quotaCmd, "-x", "-f", mountpoint, "-c", command)

	return cmd, nil
}

// SupportsQuotas determines whether the filesystem supports quotas.
func SupportsQuotas(mountpoint string, qType QuotaType) (bool, error) {
	cmd, err := runXFSQuotaCommand(mountpoint, "state -p")
	if err != nil {
		return false, err
	}
	data, err := cmd.Output()
	if err != nil {
		return false, err
	}
	if qType == FSQuotaEnforcing {
		return strings.Contains(string(data), "Enforcement: ON"), nil
	}
	return strings.Contains(string(data), "Accounting: ON"), nil
}

// IsFilesystemOfType determines whether the filesystem specified is of the type
// specified by the magic number and whether it supports quotas
func IsFilesystemOfType(mountpoint string, backingDev string, magic int64) bool {
	var buf syscall.Statfs_t
	err := syscall.Statfs(mountpoint, &buf)
	if err != nil {
		klog.V(3).Infof("Extfs Unable to statfs %s: %v", mountpoint, err)
		return false
	}
	if int64(buf.Type) != magic {
		return false
	}
	if answer, _ := SupportsQuotas(mountpoint, FSQuotaAccounting); answer {
		return true
	}
	return false
}

// GetQuotaOnDir retrieves the quota ID (if any) associated with the specified directory
// If we can't make system calls, all we can say is that we don't know whether
// it has a quota, and higher levels have to make the call.
func GetQuotaOnDir(path string) (QuotaID, error) {
	return UnknownQuotaID, nil
}

// SetQuotaOnDir applies a quota to the specified directory under the specified mountpoint.
func SetQuotaOnDir(path string, mountpoint string, id QuotaID, bytes int64) error {
	cmd, err := runXFSQuotaCommand(mountpoint, fmt.Sprintf("limit -p bhard=%v bsoft=%v %v", bytes, bytes, id))
	if err != nil {
		return err
	}
	_, err = cmd.CombinedOutput()
	if err != nil {
		return err
	}

	cmd, err = runXFSQuotaCommand(mountpoint, fmt.Sprintf("project -s -p %s %v", path, id))
	if err != nil {
		return err
	}
	_, err = cmd.CombinedOutput()
	return err
}

// GetConsumption returns the consumption in bytes if available via quotas
func GetConsumption(mountpoint string, id QuotaID) (int64, error) {
	cmd, err := runXFSQuotaCommand(mountpoint, fmt.Sprintf("quota -p -N -b -n -v %v", id))
	if err != nil {
		klog.V(3).Infof(">>>GetConsumption(1) -> %v", err)
		return 0, err
	}
	data, err := cmd.Output()
	if err != nil {
		klog.V(3).Infof(">>>GetConsumption(2) -> %v", err)
		return 0, err
	}
	match := quotaParseRegexp.FindStringSubmatch(string(data))
	if match == nil {
		klog.V(3).Infof(">>>Unable to parse quota output (1) %s", string(data))
		return 0, fmt.Errorf("Unable to parse quota output %s", string(data))
	}
	size, err := strconv.ParseInt(match[1], 10, 64)
	if match == nil {
		klog.V(3).Infof(">>>Unable to parse quota output (2) %s", string(data))
		return 0, fmt.Errorf("Unable to parse quota output %s", string(data))
	}
	klog.V(3).Infof(">>>Returning %v (%s)", size*1024, string(data))
	return size * 1024, nil
}

// GetInodes returns the inodes in use if available via quotas
func GetInodes(mountpoint string, id QuotaID) (int64, error) {
	cmd, err := runXFSQuotaCommand(mountpoint, fmt.Sprintf("quota -p -N -i -n -v %v", id))
	if err != nil {
		klog.V(3).Infof(">>>GetInodes(3) -> %v", err)
		return 0, err
	}
	data, err := cmd.Output()
	if err != nil {
		klog.V(3).Infof(">>>GetInodes(2) -> %v", err)
		return 0, err
	}
	match := quotaParseRegexp.FindStringSubmatch(string(data))
	if match == nil {
		klog.V(3).Infof(">>>Unable to parse quota output (1) %s", string(data))
		return 0, fmt.Errorf("Unable to parse quota output %s", string(data))
	}
	inodes, err := strconv.ParseInt(match[1], 10, 64)
	if match == nil {
		klog.V(3).Infof(">>>Unable to parse quota output (2) %s", string(data))
		return 0, fmt.Errorf("Unable to parse quota output %s", string(data))
	}
	klog.V(3).Infof(">>>Returning %v", inodes)
	return inodes, nil
}

// QuotaIDIsInUse checks whether the specified quota ID is in use on the specified
// filesystem
func QuotaIDIsInUse(mountpoint string, id QuotaID) (bool, error) {
	bytes, err := GetConsumption(mountpoint, id)
	if err != nil {
		return false, err
	}
	if bytes > 0 {
		return true, nil
	}
	inodes, err := GetInodes(mountpoint, id)
	return inodes > 0, err
}
