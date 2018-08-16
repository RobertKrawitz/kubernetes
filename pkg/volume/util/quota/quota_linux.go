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
	"sync"

	"k8s.io/klog"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/kubernetes/pkg/volume/util/quota/util"
	"k8s.io/kubernetes/pkg/volume/util/quota/xfs"
)

// Pod -> ID
var podQuotaMap = make(map[string]quotaUtils.QuotaID)

// Dir -> ID (for convenience)
var dirQuotaMap = make(map[string]quotaUtils.QuotaID)

// ID -> pod
var quotaPodMap = make(map[quotaUtils.QuotaID]string)

// Directory -> pod
var dirPodMap = make(map[string]string)

// Pod -> refcount
var podDirCountMap = make(map[string]int)

// ID -> size
var quotaSizeMap = make(map[quotaUtils.QuotaID]int64)
var quotaLock sync.RWMutex

var supportsQuotasMap = make(map[string]bool)
var supportsQuotasLock sync.RWMutex

const (
	// XXXXXXX Need a better way of doing this...
	firstQuota quotaUtils.QuotaID = 1048577
)

func idIsInUse(path string, id quotaUtils.QuotaID) (bool, error) {
	// First check /etc/project and /etc/projid to see if project
	// is listed; if it is we consider it in use.
	if quotaUtils.ProjectIsKnown(id) {
		return true, nil
	} else {
		isInUse, err := quotaXfs.QuotaIDIsInUse(path, id)
		return isInUse, err
	}
}

func setQuotaOnDir(path string, id quotaUtils.QuotaID, bytes int64) error {
	return quotaXfs.SetQuotaOnDir(path, id, bytes)
}

func getQuotaOnDir(m mount.Interface, path string) (quotaUtils.QuotaID, error) {
	_, _, err := quotaUtils.GetFSInfo(m, path)
	if err != nil {
		return quotaUtils.BadQuotaID, err
	}
	id, err := quotaXfs.GetQuotaOnDir(path)
	return id, err
}

func clearQuotaOnDir(m mount.Interface, path string) error {
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
	quotaUtils.ClearFSInfo(path)
	// If we couldn't get a quota, that's fine -- there may
	// never have been one, and we have no way to know otherwise
	return nil
}

// SupportsQuotas -- Does the path support quotas
func SupportsQuotas(m mount.Interface, path string) (bool, error) {
	supportsQuotasLock.Lock()
	defer supportsQuotasLock.Unlock()
	if supportsQuotas, ok := supportsQuotasMap[path]; ok {
		return supportsQuotas, nil
	}
	mount, dev, err := quotaUtils.GetFSInfo(m, path)
	klog.V(3).Infof("SupportsQuotas %s -> mount %s dev %s %v", path, mount, dev, err)
	if err != nil {
		supportsQuotasMap[path] = false
		return false, err
	}
	supportsQuotas, err := quotaXfs.SupportsQuotas(dev)
	supportsQuotasMap[path] = supportsQuotas
	klog.V(3).Infof("      SupportsQuotas -> %v", supportsQuotas)
	return supportsQuotas, err
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
kklog.V(3).Infof("Synthesizing pod ID %s for directory %s in AssignQuota", poduid, path)
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
	for id := firstQuota; id == id; id++ {
		if _, ok := quotaPodMap[id]; ok {
			continue
		}
		isInUse, err := idIsInUse(path, id)
		if err != nil {
			return err
		} else if isInUse {
			klog.V(3).Infof("Project ID %v is in use, trying again", id)
			continue
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
	return fmt.Errorf("Unable to find a quota ID for %s", path)
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
func GetConsumption(path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	id, ok := dirQuotaMap[path]
	if !ok {
		return 0, fmt.Errorf("No quota available for %s", path)
	}
	size, error := quotaXfs.GetConsumption(path, id)
	return size, error
}

// GetInodes -- retrieve the number of inodes in use under the directory
func GetInodes(path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	id, ok := dirQuotaMap[path]
	if !ok {
		return 0, fmt.Errorf("No quota available for %s", path)
	}
	inodes, error := quotaXfs.GetInodes(path, id)
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
	return err
}
