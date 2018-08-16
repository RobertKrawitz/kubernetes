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

package quotaXfs

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
	"unsafe"

	"golang.org/x/sys/unix"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/volume/util/quota/util"
)

const (
	linuxXfsMagic = 0x58465342
	// Documented in man xfs_quota(8); not necessarily the same
	// as the filesystem blocksize
	quotaBsize        = 512
	bitsPerWord       = 32 << (^uint(0) >> 63) // either 32 or 64
	maxInt      int64 = 1<<(bitsPerWord-1) - 1 // either 1<<31 - 1 or 1<<63 - 1
)

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

// SupportsQuotas -- does this backing device support quotas that
// can be applied to directories?
func SupportsQuotas(backingDev string) (bool, error) {
	// For now, we're only going to do quotas on XFS
	var qstat C.fs_quota_stat_t

	// And this is an XFS-specific quota call
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, uintptr(C.Q_XGETQSTAT_PRJQUOTA), uintptr(unsafe.Pointer(C.CString(backingDev))), 0, uintptr(unsafe.Pointer(&qstat)), 0, 0)
	if errno == 0 {
		return qstat.qs_flags&C.FS_QUOTA_PDQ_ENFD > 0 && qstat.qs_flags&C.FS_QUOTA_PDQ_ACCT > 0, nil
	}
	klog.V(3).Infof("detectSupportQuota %s FAILED %v", backingDev, errno)
	return false, errno
}

// GetQuotaOnDir -- get the quota ID that applies to this directory.
func GetQuotaOnDir(path string) (quotaUtils.QuotaID, error) {
	dir, err := openDir(path)
	if err != nil {
		klog.V(3).Infof("Can't open directory %s: %#+v", path, err)
		return quotaUtils.BadQuotaID, err
	}
	defer closeDir(dir)
	var fsx C.struct_fsxattr
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSGETXATTR,
		uintptr(unsafe.Pointer(&fsx)))
	if errno != 0 {
		return quotaUtils.BadQuotaID, fmt.Errorf("Failed to get quota ID for %s: %v", path, errno.Error())
	}
	return quotaUtils.QuotaID(fsx.fsx_projid), nil
}

// ASetQuotaOnDir -- npply the specified quota to the directory.  If
// bytes is not greater than zero, the quota should be applied in a
// way that is non-enforcing (either explicitly so or by setting a
// quota larger than anything the user may possibly create)
func SetQuotaOnDir(path string, id quotaUtils.QuotaID, bytes int64) error {
	klog.V(3).Infof("xfsSetQuotaOn %s ID %v bytes %v", path, id, bytes)

	backingFsBlockDev, ok := quotaUtils.GetBackingDev(path)
	if ok != nil {
		return fmt.Errorf("Cannot find backing device for %s", path)
	}

	if bytes < 0 {
		bytes = maxInt
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
	return nil
}

// QuotaIDIsInUse -- determine whether the quota ID is already in
// use.
func QuotaIDIsInUse(path string, id quotaUtils.QuotaID) (bool, error) {
	backingFsBlockDev, err := quotaUtils.GetBackingDev(path)
	if err != nil {
		// If GetBackingDev fails once, it will fail for any other project ID
		return false, err
	}

	var d C.fs_disk_quota_t

	var cs = C.CString(backingFsBlockDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, C.Q_XGETPQUOTA,
		uintptr(unsafe.Pointer(cs)), uintptr(C.__u32(id)),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	return errno == 0, nil
}

func getConsumptionInternal(path string, id quotaUtils.QuotaID, typearg string) (int64, error) {
	backingFsBlockDev, err := quotaUtils.GetBackingDev(path)
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
		klog.V(3).Infof("Consumption for %s is %v", path, d.d_bcount*512)
		return int64(d.d_bcount) * quotaBsize, nil
	case "i":
		klog.V(3).Infof("Inode consumption for %s is %v", path, d.d_icount)
		return int64(d.d_icount), nil
	default:
		return 0, fmt.Errorf("Unknown quota type %s", typearg)
	}
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
func GetConsumption(path string, id quotaUtils.QuotaID) (int64, error) {
	inodes, err := getConsumptionInternal(path, id, "b")
	return inodes, err
}

// GetInodes -- retrieve the number of inodes in use under the directory
func GetInodes(path string, id quotaUtils.QuotaID) (int64, error) {
	inodes, err := getConsumptionInternal(path, id, "i")
	return inodes, err
}
