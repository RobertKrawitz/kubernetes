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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"k8s.io/klog"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/volume/util/quota/common"
	"k8s.io/kubernetes/pkg/volume/util/quota/xfs"
)

// Pod -> ID
var podQuotaMap = make(map[string]common.QuotaID)

// Dir -> ID (for convenience)
var dirQuotaMap = make(map[string]common.QuotaID)

// ID -> pod
var quotaPodMap = make(map[common.QuotaID]string)

// Directory -> pod
var dirPodMap = make(map[string]string)

// Backing device -> applier
// This is *not* cleaned up; its size will be bounded.
var devApplierMap = make(map[string]common.LinuxVolumeQuotaApplier)

// Directory -> applier
var dirApplierMap = make(map[string]common.LinuxVolumeQuotaApplier)

// Pod -> refcount
var podDirCountMap = make(map[string]int)

// ID -> size
var quotaSizeMap = make(map[common.QuotaID]int64)
var quotaLock sync.RWMutex

var supportsQuotasMap = make(map[string]bool)
var supportsQuotasLock sync.RWMutex

var mountParseRegexp *regexp.Regexp = regexp.MustCompilePOSIX("^([^ ]*)[ \t]*([^ ]*)[ \t]*([^ ]*)") // Ignore options etc.

var projectsParseRegexp *regexp.Regexp = regexp.MustCompilePOSIX("^([[:digit:]]+):")
var projidParseRegexp *regexp.Regexp = regexp.MustCompilePOSIX("[^#]:([[:digit:]]+)$")

// Directory -> backingDev
var backingDevMap = make(map[string]string)
var backingDevLock sync.RWMutex

var mountpointMap = make(map[string]string)
var mountpointLock sync.RWMutex

const (
	mountsFile   = "/proc/self/mounts"
	projectsFile = "/etc/projects"
	projidFile   = "/etc/projid"
)

var providers = []common.LinuxVolumeQuotaProvider{
	&xfs.VolumeProvider{},
}

// Separate the innards for ease of testing
func detectBackingDevInternal(mountpoint string, mounts string) (string, error) {
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

// detectBackingDev assumes that the mount point provided is valid
func detectBackingDev(_ mount.Interface, mountpoint string) (string, error) {
	dev, err := detectBackingDevInternal(mountpoint, mountsFile)
	return dev, err
}

// GetBackingDev returns the mount point for the specified path
// It assumes that we already know the backing device for the path.
func GetBackingDev(path string) (string, error) {
	backingDevLock.Lock()
	defer backingDevLock.Unlock()
	if backingDev, ok := backingDevMap[path]; ok {
		return backingDev, nil
	}
	return "/", fmt.Errorf("Backing device not found for %s", path)
}

func clearBackingDev(path string) {
	backingDevLock.Lock()
	defer backingDevLock.Unlock()
	delete(backingDevMap, path)
}

// Assumes that the path has been fully canonicalized
// Breaking this up helps with testingxs
func detectMountpointInternal(m mount.Interface, path string) (string, error) {
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

func detectMountpoint(m mount.Interface, path string) (string, error) {
	xpath, err := filepath.Abs(path)
	if err != nil {
		return "/", err
	}
	xpath, err = filepath.EvalSymlinks(xpath)
	if err != nil {
		return "/", err
	}
	xpath, err = detectMountpointInternal(m, xpath)
	return xpath, err
}

// GetMountpoint returns the mount point for the specified path
// It assumes that we already know the mountpoint for the path.
func GetMountpoint(path string) (string, error) {
	mountpointLock.Lock()
	defer mountpointLock.Unlock()
	if mountpoint, ok := mountpointMap[path]; ok {
		return mountpoint, nil
	}
	return "/", fmt.Errorf("Backing device not found for %s", path)
}

func clearMountpoint(path string) {
	mountpointLock.Lock()
	defer mountpointLock.Unlock()
	delete(mountpointMap, path)
}

// getFSInfo Returns mountpoint and backing device
// getFSInfo should cache the mountpoint and backing device for the
// path.
func getFSInfo(m mount.Interface, path string) (string, string, error) {
	mountpointLock.Lock()
	defer mountpointLock.Unlock()

	backingDevLock.Lock()
	defer backingDevLock.Unlock()

	var err error

	mountpoint, okMountpoint := mountpointMap[path]
	if !okMountpoint {
		mountpoint, err = detectMountpoint(m, path)
		klog.V(3).Infof("Mountpoint %s -> %s (%v)", path, mountpoint, err)
		if err != nil {
			return "", "", err
		}
		mountpointMap[path] = mountpoint
	}

	backingDev, okBackingDev := backingDevMap[path]
	if !okBackingDev {
		backingDev, err = detectBackingDev(m, mountpoint)
		klog.V(3).Infof("Backing dev %s -> %s (%v)", path, backingDev, err)
		if err != nil {
			return "", "", err
		}
		backingDevMap[path] = backingDev
	}
	return mountpoint, backingDev, nil
}

func clearFSInfo(path string) {
	clearMountpoint(path)
	clearBackingDev(path)
}

func projectIsPresentInFile(id common.QuotaID, file string, re *regexp.Regexp) bool {
	fd, err := os.Open(file)
	if err != nil {
		return false
	}
	defer fd.Close()
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		match := re.FindStringSubmatch(scanner.Text())
		if match != nil {
			pid := match[1]
			if i, err := strconv.Atoi(pid); err == nil && int(id) == i {
				return true
			}
		}
	}
	return false
}

// projectisknown -- project is known to the system (in /etc/project,
// /etc/projid, or similar)
func projectIsKnown(id common.QuotaID) bool {
	return projectIsPresentInFile(id, projectsFile, projectsParseRegexp) ||
		projectIsPresentInFile(id, projidFile, projidParseRegexp)
}

func idIsInUse(path string, id common.QuotaID) (bool, error) {
	// First check /etc/project and /etc/projid to see if project
	// is listed; if it is we consider it in use.
	if !projectIsKnown(id) {
		isInUse, err := dirApplierMap[path].QuotaIDIsInUse(path, id)
		return isInUse, err
	}
	return true, nil
}

func setQuotaOnDir(path string, id common.QuotaID, bytes int64) error {
	return dirApplierMap[path].SetQuotaOnDir(path, id, bytes)
}

func getQuotaOnDir(m mount.Interface, path string) (common.QuotaID, error) {
	_, _, err := getFSInfo(m, path)
	if err != nil {
		return common.BadQuotaID, err
	}
	id, err := dirApplierMap[path].GetQuotaOnDir(path)
	return id, err
}

func clearQuotaOnDir(m mount.Interface, path string) error {
	// Since we may be called without path being in the map,
	// we excplicitly have to check in this case.
	supportsQuotas, err := SupportsQuotas(m, path)
	if !supportsQuotas {
		return nil
	}
	projid, err := getQuotaOnDir(m, path)
	if err == nil {
		// This means that we have a quota on the directory but
		// we can't clear it.  That's not good.
		err = setQuotaOnDir(path, projid, 0)
		if err != nil {
			klog.V(3).Infof("Attempt to clear quota failed: %v", err)
		}
		return err
	}
	clearFSInfo(path)
	// If we couldn't get a quota, that's fine -- there may
	// never have been one, and we have no way to know otherwise
	return nil
}

// SupportsQuotas -- Does the path support quotas
// Cache the applier for paths that support quotas.  For paths that don't,
// don't cache the result because nothing will clean it up.
// However, do cache the device->applier map; the number of devices
// is bounded.
func SupportsQuotas(m mount.Interface, path string) (bool, error) {
	supportsQuotasLock.Lock()
	defer supportsQuotasLock.Unlock()
	if supportsQuotas, ok := supportsQuotasMap[path]; ok {
		return supportsQuotas, nil
	}
	mount, dev, err := getFSInfo(m, path)
	klog.V(3).Infof("SupportsQuotas %s -> mount %s dev %s %v", path, mount, dev, err)
	if err != nil {
		return false, err
	}
	// Do we know about this device?
	applier, ok := devApplierMap[path]
	if ok {
		if applier != nil {
			dirApplierMap[path] = applier
		}
		return applier != nil, nil
	}
	for _, provider := range providers {
		applier = provider.GetQuotaApplier(dev)
		if applier != nil {
			supportsQuotasMap[path] = true
			dirApplierMap[path] = applier
			return true, nil
		}
	}
	return false, nil
}

func findAvailableQuotaID(path string) (common.QuotaID, error) {
/*
	for id := common.FirstQuota; id == id; id++ {
		if _, ok := quotaPodMap[id]; ok {
			continue
		}
		isInUse, err := idIsInUse(path, id)
		if err != nil {
			return common.BadQuotaID, err
		} else if isInUse {
			klog.V(3).Infof("Project ID %v is in use, trying again", id)
			continue
		}
		return id, nil
	}
	return common.BadQuotaID, fmt.Errorf("Can't find available quota ID")
*/
	id, err := createQuotaID(path)
	return id, err
}

// AssignQuota -- assign a quota to the specified directory.
// AssignQuota chooses the quota ID based on the pod UID and path.
// If the pod UID is identical to another one known, it may (but presently
// doesn't) choose the same quota ID as other volumes in the pod.
func AssignQuota(m mount.Interface, path string, poduid string, bytes int64) error {
	ok, err := SupportsQuotas(m, path)
	if !ok {
		return fmt.Errorf("Quotas not supported on %s: %v", path, err)
	}
	quotaLock.Lock()
	defer quotaLock.Unlock()
	// Current policy is to set individual quotas on each volumes.
	// If we decide later that we want to assign one quota for all
	// volumes in a pod, we can simply remove this line of code.
	// If and when we decide permanently that we're going to adop
	// one quota per volume, we can rip all of the pod code out.
	poduid = string(uuid.NewUUID())
	klog.V(3).Infof("Synthesizing pod ID %s for directory %s in AssignQuota", poduid, path)
	pod, ok := dirPodMap[path]
	if ok {
		if pod != poduid {
			return fmt.Errorf("Requesting quota on existing directory %s but different pod %s %s", path, pod, poduid)
		}
	}
	id, ok := podQuotaMap[poduid]
	if ok {
		if quotaSizeMap[id] != bytes {
			return fmt.Errorf("Requesting quota of different size: old %v new %v", quotaSizeMap[id], bytes)
		}
		err = setQuotaOnDir(path, id, bytes)
		if err == nil {
			dirQuotaMap[path] = id
			dirPodMap[path] = poduid
		}
		return err
	}
	id, err = findAvailableQuotaID(path)
	if err != nil {
		return err
	}
	err = setQuotaOnDir(path, id, bytes)
	if err != nil {
		klog.V(3).Infof("Assign quota FAILED %v", err)
		return err
	}
	quotaPodMap[id] = poduid
	quotaSizeMap[id] = bytes
	podQuotaMap[poduid] = id
	dirQuotaMap[path] = id
	dirPodMap[path] = poduid
	if count, ok := podDirCountMap[poduid]; ok {
		podDirCountMap[poduid] = count + 1
	} else {
		podDirCountMap[poduid] = 1
	}
	return nil
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
func GetConsumption(path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	applier := dirApplierMap[path]
	if applier == nil {
		return 0, fmt.Errorf("No quota available for %s", path)
	}
	size, error := applier.GetConsumption(path, dirQuotaMap[path])
	return size, error
}

// GetInodes -- retrieve the number of inodes in use under the directory
func GetInodes(path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	applier := dirApplierMap[path]
	if applier == nil {
		return 0, fmt.Errorf("No quota available for %s", path)
	}
	inodes, error := applier.GetInodes(path, dirQuotaMap[path])
	return inodes, error
}

// ClearQuota -- remove the quota assigned to a directory
func ClearQuota(m mount.Interface, path string) error {
	klog.V(3).Infof("ClearQuota %s", path)
	quotaLock.Lock()
	defer quotaLock.Unlock()
	poduid, ok := dirPodMap[path]
	if !ok {
		// Nothing in the map either means that there was no
		// quota to begin with or that we're clearing a
		// stale directory, so if we find a quota, just remove it.
		return clearQuotaOnDir(m, path)
	}
	_, ok = podQuotaMap[poduid]
	if !ok {
		return fmt.Errorf("ClearQuota: No quota available for %s", path)
	}
	var err error
	projid, err := getQuotaOnDir(m, path)
	if projid != dirQuotaMap[path] {
		klog.V(3).Infof("Expected quota ID %v on dir %s does not match actual %v", dirQuotaMap[path], path, projid)
		return fmt.Errorf("Expected quota ID %v on dir %s does not match actual %v", dirQuotaMap[path], path, projid)
	}
	podDirCountMap[poduid]--
	if podDirCountMap[poduid] == 0 {
		err = clearQuotaOnDir(m, path)
		if err != nil {
			klog.V(3).Infof("Unable to clear quota %v %s: %v", dirQuotaMap[path], path, err)
		} else {
			err = removeQuotaID(projid)
			if err != nil {
				klog.V(3).Infof("removeQuotaID %v failed: %v", projid, err)
			}
		}
		delete(quotaSizeMap, podQuotaMap[poduid])
		delete(quotaPodMap, podQuotaMap[poduid])
		delete(podDirCountMap, poduid)
		delete(podQuotaMap, poduid)
	} else {
		klog.V(3).Infof("Not clearing quota for pod %s; still %v dirs outstanding", poduid, podDirCountMap[poduid])
	}
	delete(dirPodMap, path)
	delete(dirQuotaMap, path)
	delete(dirApplierMap, path)
	return err
}
