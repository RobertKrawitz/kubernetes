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

/*
#include <stdlib.h>
#include <dirent.h>
#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>
#include <errno.h>

#ifndef FS_XFLAG_PROJINHERIT
struct fsxattr {
	__u32		fsx_xflags;
	__u32		fsx_extsize;
	__u32		fsx_nextents;
	__u32		fsx_projid;
	unsigned char	fsx_pad[12];
};
#define FS_XFLAG_PROJINHERIT	0x00000200
#endif
#ifndef FS_IOC_FSGETXATTR
#define FS_IOC_FSGETXATTR		_IOR ('X', 31, struct fsxattr)
#endif
#ifndef FS_IOC_FSSETXATTR
#define FS_IOC_FSSETXATTR		_IOW ('X', 32, struct fsxattr)
#endif

#ifndef PRJQUOTA
#define PRJQUOTA	2
#endif
#ifndef XFS_PROJ_QUOTA
#define XFS_PROJ_QUOTA	2
#endif
#ifndef Q_XSETPQLIM
#define Q_XSETPQLIM QCMD(Q_XSETQLIM, PRJQUOTA)
#endif
#ifndef Q_XGETPQUOTA
#define Q_XGETPQUOTA QCMD(Q_XGETQUOTA, PRJQUOTA)
#endif

const int Q_XGETQSTAT_PRJQUOTA = QCMD(Q_XGETQSTAT, PRJQUOTA);
*/
import "C"

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"regexp"
	"unsafe"
	"bufio"
	"strconv"

	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/util/mount"
	"k8s.io/apimachinery/pkg/util/uuid"
	"golang.org/x/sys/unix"
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

// Directory -> backingDev
var backingDevsMap = make(map[string]string)
var backingDevLock sync.RWMutex

var supportsQuotasMap = make(map[string]bool)
var supportsQuotasLock sync.RWMutex

var quotaParseRegexp *regexp.Regexp = regexp.MustCompile("^[^ \t]*[ \t]*([123456789][0123456789]*)")

var mountParseRegexp *regexp.Regexp = regexp.MustCompile("^(/[^ ]*)[ \t]*([^ ]*)[ \t]*([^ ]*)") // Ignore options etc.

var projectsParseRegexp *regexp.Regexp = regexp.MustCompile("^([0123456789][0123456789]*):")
var projidParseRegexp *regexp.Regexp = regexp.MustCompile("^[^:#][^:#]*:([0123456789][0123456789]*)")

const (
	linuxXfsMagic = 0x58465342
	// Documented in man xfs_quota(8); not necessarily the same
	// as the filesystem blocksize
	quotaBsize = 512
	// XXXXXXX Need a better way of doing this...
	firstQuota QuotaID = 1048577
	// Location of mount table
	mountsFile = "/proc/self/mounts"
	projectsFile = "/etc/projects"
	projidFile = "/etc/projid"
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
			return xpath, nil
 		}
 		xpath = filepath.Dir(xpath)
	}
	return "/", nil
}

func free(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func openDir(path string) (*C.DIR, error) {
	Cpath := C.CString(path)
	defer free(Cpath)

	dir := C.opendir(Cpath)
	if dir == nil {
		return nil, fmt.Errorf("Can't open dir")
	}
	return dir, nil
}

func closeDir(dir *C.DIR) {
	if dir != nil {
		C.closedir(dir)
	}
}

func getDirFd(dir *C.DIR) uintptr {
	return uintptr(C.dirfd(dir))
}

func detectBackingDev(m mount.Interface, path string) (error) {
	mountpoint, err := detectMountpoint(m, path)
	if err != nil {
		return err
	}
	file, err := os.Open(mountsFile)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := mountParseRegexp.FindStringSubmatch(scanner.Text())
		if match != nil {
			device := match[1]
			mount := match[2]
			if mount == mountpoint {
				backingDevsMap[path] = device
				return nil
			}
		}
	}
	klog.V(3).Infof("Couldn't find backing device for %s!", path)
	return nil
}

// getBackingDev returns the mount point for the specified path
// It assumes the map has already been created; we don't get a mount
// interface here to look for it!
func getBackingDev(path string) (string, error) {
	backingDevLock.Lock()
	defer backingDevLock.Unlock()
	if backingDev, ok := backingDevsMap[path]; ok {
		return backingDev, nil
	}
	return "/", fmt.Errorf("Backing device not found for %s", path);
}

func detectSupportsQuotas(path string) (bool, error) {
	// For now, we're only going to do quotas on XFS
	var qstat C.fs_quota_stat_t

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, uintptr(C.Q_XGETQSTAT_PRJQUOTA), uintptr(unsafe.Pointer(C.CString(path))), 0, uintptr(unsafe.Pointer(&qstat)), 0, 0)
	if errno == 0 {
		if qstat.qs_flags&C.FS_QUOTA_PDQ_ENFD > 0 && qstat.qs_flags&C.FS_QUOTA_PDQ_ACCT > 0 {
			klog.V(3).Infof("detectSupportQuota %s YES", path)
			return true, nil
		} else {
			klog.V(3).Infof("detectSupportQuota %s NO", path)
			return false, nil
		}
	}
	klog.V(3).Infof("detectSupportQuota %s FAILED %v", path, errno)
	return false, errno
}

// Does the path support quotas
func SupportsQuotas(m mount.Interface, path string) (bool, error) {
	supportsQuotasLock.Lock()
	defer supportsQuotasLock.Unlock()
	if quotas, ok := supportsQuotasMap[path]; ok {
		return quotas, nil
	}
	err := detectBackingDev(m, path)
	if err != nil {
		klog.V(3).Infof("SupportsQuotas failed %v", err)
		return false, err
	}
	supportsQuotas, err := detectSupportsQuotas(backingDevsMap[path])
	if err != nil {
		klog.V(3).Infof("SupportsQuotas failed %v", err)
	}
	supportsQuotasMap[path] = supportsQuotas
	return supportsQuotas, err
}

func getQuotaOnDir(m mount.Interface, path string) (QuotaID, error) {
	if quotas, _ := SupportsQuotas(m, path); !quotas {
		return 0, fmt.Errorf("getQuotaOnDir: %s does not support quotas", path)
	}
	dir, err := openDir(path)
	if err != nil {
		klog.V(3).Infof("Can't open directory %s: %#+v", path, err)
		return 0, err
	}
	defer closeDir(dir)
	var fsx C.struct_fsxattr
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSGETXATTR,
		uintptr(unsafe.Pointer(&fsx)))
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get quota ID for %s: %v", path, errno.Error())
	}
	return QuotaID(fsx.fsx_projid), nil
}


func setQuotaOn(path string, id QuotaID, bytes int64) error {
	klog.V(3).Infof("setQuotaOn %s ID %v bytes %v", path, id, bytes)

	backingFsBlockDev, ok := getBackingDev(path)
	if ok != nil {
		return fmt.Errorf("Cannot find backing device for %s", path)
	}

	var d C.fs_disk_quota_t
	d.d_version = C.FS_DQUOT_VERSION
	d.d_id = C.__u32(id)
	d.d_flags = C.XFS_PROJ_QUOTA

	d.d_fieldmask = C.FS_DQ_BHARD
	d.d_blk_hardlimit = C.__u64(bytes / 512)
	d.d_blk_softlimit = d.d_blk_hardlimit

	var cs = C.CString(backingFsBlockDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, C.Q_XSETPQLIM,
		uintptr(unsafe.Pointer(cs)), uintptr(d.d_id),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	if errno != 0 {
		return fmt.Errorf("Failed to set quota limit for ID %d on %s: %v",
			id, path, errno.Error())
	}
	if (bytes > 0) {
		dir, err := openDir(path)
		if err != nil {
			return err
		}
		defer closeDir(dir)

		var fsx C.struct_fsxattr
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSGETXATTR,
			uintptr(unsafe.Pointer(&fsx)))
		if errno != 0 {
			return fmt.Errorf("Failed to get quota ID for %s: %v", path, errno.Error())
		}
		fsx.fsx_projid = C.__u32(id)
		fsx.fsx_xflags |= C.FS_XFLAG_PROJINHERIT
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSSETXATTR,
			uintptr(unsafe.Pointer(&fsx)))
		if errno != 0 {
			return fmt.Errorf("Failed to set quota ID for %s: %v", path, errno.Error())
		}
	}
	return nil
}

func projectIsPresent(id QuotaID, file string, re *regexp.Regexp) bool {
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

func idIsInUse(path string, id QuotaID) bool {
	// First check /etc/project and /etc/projid to see if project
	// is listed; if it is we consider it in use.
	if projectIsPresent(id, projectsFile, projectsParseRegexp) ||
		projectIsPresent(id, projidFile, projidParseRegexp) {
		return true
	}

	backingFsBlockDev, err := getBackingDev(path)
	if err != nil {
		return false
	}

	var d C.fs_disk_quota_t

	var cs = C.CString(backingFsBlockDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, C.Q_XGETPQUOTA,
		uintptr(unsafe.Pointer(cs)), uintptr(C.__u32(id)),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	if errno != 0 {
		return false
	} else {
		return true
	}
}

func AssignQuota(m mount.Interface, path string, poduid string, bytes int64) (QuotaID, error) {

	ok, err := SupportsQuotas(m, path)
	if !ok {
		return BadQuota, fmt.Errorf("Quotas not supported on %s: %v", path, err)
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
		if _, ok := quotaPodMap[id]; ok {
			continue
		}
		if idIsInUse(path, id) {
			klog.V(3).Infof("Project ID %v is in use, try again", id)
			continue
		}
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

func internalGetConsumption(path string, typearg string) (int64, error) {
	id, ok := dirQuotaMap[path]
	if !ok {
		return 0, fmt.Errorf("No quota available for %s", path);
	}
	backingFsBlockDev, err := getBackingDev(path)
	if err != nil {
		return 0, fmt.Errorf("Cannot find backing device for %s", path)
	}

	var d C.fs_disk_quota_t

	var cs = C.CString(backingFsBlockDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, C.Q_XGETPQUOTA,
		uintptr(unsafe.Pointer(cs)), uintptr(C.__u32(id)),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get consumption for dir %s: %v",
			path, errno.Error())
	}

	switch typearg {
	case "b":
		klog.V(3).Infof("Consumption for %s is %v", path, d.d_bcount * 512)
		return int64(d.d_bcount) * quotaBsize, nil
	case "i":
		klog.V(3).Infof("Inode consumption for %s is %v", path, d.d_icount)
		return int64(d.d_icount), nil
	default:
		return 0, fmt.Errorf("Unknown quota type %s", typearg)
	}
}

func GetConsumption(path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	size, error := internalGetConsumption(path, "b")
	return size, error
}

func GetInodes(path string) (int64, error) {
	// Note that we actually need to hold the lock at least through
	// running the quota command, so it can't get recycled behind our back
	quotaLock.Lock()
	defer quotaLock.Unlock()
	inodes, error := internalGetConsumption(path, "i")
	return inodes, error
}

func ClearQuota(m mount.Interface, path string) (error) {
	klog.V(3).Infof("ClearQuota %s", path)
	quotaLock.Lock()
	defer quotaLock.Unlock()
	poduid, ok := dirPodMap[path]
	if !ok {
		// Nothing in the map either means that there was no
		// quota to begin with or that we're clearing a
		// stale directory, so if we find a quota, just remove it.
		pid, err := getQuotaOnDir(m, path)
		if err == nil {
			// Any error here is real
			err = setQuotaOn(path, pid, 0)
			if err != nil {
				klog.V(3).Infof("Attempt to clear quota failed: %v", err)
			}
			return err
		}
		// If we couldn't get a quota, that's fine -- there may
		// never have been one, and we have no way to know otherwise
		return nil
	}
	_, ok = podQuotaMap[poduid]
	if !ok {
		return fmt.Errorf("ClearQuota: No quota available for %s", path)
	}
	var err error
	pid, err := getQuotaOnDir(m, path)
	if pid != dirQuotaMap[path] {
		klog.V(3).Infof("Expected quota ID %v on dir %s does not match actual", dirQuotaMap[path], path, pid)
		return fmt.Errorf("Expected quota ID %v on dir %s does not match actual", dirQuotaMap[path], path, pid)
	}
	podDirCountMap[poduid]--
	if podDirCountMap[poduid] == 0 {
		err = setQuotaOn(path, dirQuotaMap[path], 0)
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
	backingDevLock.Lock()
	delete(backingDevsMap, path)
	backingDevLock.Unlock()
	supportsQuotasLock.Lock()
	delete(supportsQuotasMap, path)
	supportsQuotasLock.Unlock()
	return err
}
