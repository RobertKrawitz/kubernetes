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

package xfs

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
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/volume/util/quota/common"
)

// VolumeProvider supplies a quota applier to the generic code.
type VolumeProvider struct {
}

// GetQuotaApplier -- does this backing device support quotas that
// can be applied to directories?
func (*VolumeProvider) GetQuotaApplier(backingDev string) common.LinuxVolumeQuotaApplier {
	// For now, we're only going to do quotas on XFS
	var qstat C.fs_quota_stat_t
	CPath := C.CString(backingDev)
	defer free(CPath)

	// And this is an XFS-specific quota call
	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, uintptr(C.Q_XGETQSTAT_PRJQUOTA), uintptr(unsafe.Pointer(CPath)), 0, uintptr(unsafe.Pointer(&qstat)), 0, 0)
	if errno == 0 && qstat.qs_flags&C.FS_QUOTA_PDQ_ENFD > 0 && qstat.qs_flags&C.FS_QUOTA_PDQ_ACCT > 0 {
		return xfsVolumeQuota{backingDev}
	}
	return nil
}

type xfsVolumeQuota struct {
	backingDev string
}

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

// GetQuotaOnDir -- get the quota ID that applies to this directory.
func (v xfsVolumeQuota) GetQuotaOnDir(path string) (common.QuotaID, error) {
	dir, err := openDir(path)
	if err != nil {
		klog.V(3).Infof("Can't open directory %s: %#+v", path, err)
		return common.BadQuotaID, err
	}
	defer closeDir(dir)
	var fsx C.struct_fsxattr
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, getDirFd(dir), C.FS_IOC_FSGETXATTR,
		uintptr(unsafe.Pointer(&fsx)))
	if errno != 0 {
		return common.BadQuotaID, fmt.Errorf("Failed to get quota ID for %s: %v", path, errno.Error())
	}
	return common.QuotaID(fsx.fsx_projid), nil
}

// ASetQuotaOnDir -- npply the specified quota to the directory.  If
// bytes is not greater than zero, the quota should be applied in a
// way that is non-enforcing (either explicitly so or by setting a
// quota larger than anything the user may possibly create)
func (v xfsVolumeQuota) SetQuotaOnDir(path string, id common.QuotaID, bytes int64) error {
	klog.V(3).Infof("xfsSetQuotaOn %s ID %v bytes %v", path, id, bytes)

	if bytes < 0 {
		bytes = maxInt
	}

	var d C.fs_disk_quota_t
	d.d_version = C.FS_DQUOT_VERSION
	d.d_id = C.__u32(id)
	d.d_flags = C.XFS_PROJ_QUOTA

	d.d_fieldmask = C.FS_DQ_BHARD
	d.d_blk_hardlimit = C.__u64(bytes / quotaBsize)
	d.d_blk_softlimit = d.d_blk_hardlimit

	var cs = C.CString(v.backingDev)
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

func (v xfsVolumeQuota) getQuotaInfo(path string, id common.QuotaID) (C.fs_disk_quota_t, syscall.Errno) {
	var d C.fs_disk_quota_t

	var cs = C.CString(v.backingDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, C.Q_XGETPQUOTA,
		uintptr(unsafe.Pointer(cs)), uintptr(C.__u32(id)),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	return d, errno
}

// QuotaIDIsInUse -- determine whether the quota ID is already in use.
func (v xfsVolumeQuota) QuotaIDIsInUse(path string, id common.QuotaID) (bool, error) {
	_, errno := v.getQuotaInfo(path, id)
	return errno == 0, nil
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
func (v xfsVolumeQuota) GetConsumption(path string, id common.QuotaID) (int64, error) {
	d, errno := v.getQuotaInfo(path, id)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get quota for %s: %s", path, errno.Error())
	}
	klog.V(3).Infof("Consumption for %s is %v", path, d.d_bcount*quotaBsize)
	return int64(d.d_bcount) * quotaBsize, nil
}

// GetInodes -- retrieve the number of inodes in use under the directory
func (v xfsVolumeQuota) GetInodes(path string, id common.QuotaID) (int64, error) {
	d, errno := v.getQuotaInfo(path, id)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get quota for %s: %s", path, errno.Error())
	}
	klog.V(3).Infof("Inode consumption for %s is %v", path, d.d_icount)
	return int64(d.d_icount), nil
}
