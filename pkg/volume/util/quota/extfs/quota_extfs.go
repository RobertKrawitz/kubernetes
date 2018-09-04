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

package extfs

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
#ifndef EXTFS_PROJ_QUOTA
#define EXTFS_PROJ_QUOTA	2
#endif
#ifndef Q_SETPQUOTA
#define Q_SETPQUOTA (unsigned) QCMD(Q_SETQUOTA, PRJQUOTA)
#endif
#ifndef Q_GETPQUOTA
#define Q_GETPQUOTA (unsigned) QCMD(Q_GETQUOTA, PRJQUOTA)
#endif
#ifndef Q_XSETPQLIM
#define Q_XSETPQLIM QCMD(Q_XSETQLIM, PRJQUOTA)
#endif
#ifndef Q_XGETPQUOTA
#define Q_XGETPQUOTA QCMD(Q_XGETQUOTA, PRJQUOTA)
#endif
#ifndef Q_XGETQSTAT_PRJQUOTA
#define Q_XGETQSTAT_PRJQUOTA QCMD(Q_XGETQSTAT, PRJQUOTA)
#endif
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

//  ext4fs empirically has a maximum quota size of 2^48 - 1 blocks (256 petabytes)
const (
	linuxExtfsMagic       = 0xef53
	quotaBsize            = 1024                                   // extfs specific
	bitsPerWord           = 32 << (^uint(0) >> 63)                 // either 32 or 64
	maxQuota        int64 = (1<<(bitsPerWord-1) - 1) & (1<<58 - 1) // either 1<<31 - 1 or 1<<58 - 1 (max quota
)

// VolumeProvider supplies a quota applier to the generic code.
type VolumeProvider struct {
}

// GetQuotaApplier -- does this backing device support quotas that
// can be applied to directories?
func (*VolumeProvider) GetQuotaApplier(mountpoint string, backingDev string) common.LinuxVolumeQuotaApplier {
	var buf syscall.Statfs_t
	err := syscall.Statfs(mountpoint, &buf)
	if err != nil {
		klog.V(3).Infof("Extfs Unable to statfs %s: %v", mountpoint, err)
		return nil
	}
	if buf.Type != linuxExtfsMagic {
		return nil
	}

	var qstat C.fs_quota_stat_t
	CPath := C.CString(backingDev)
	defer free(CPath)

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, uintptr(C.Q_XGETQSTAT_PRJQUOTA), uintptr(unsafe.Pointer(CPath)), 0, uintptr(unsafe.Pointer(&qstat)), 0, 0)
	if errno == 0 && qstat.qs_flags&C.FS_QUOTA_PDQ_ENFD > 0 && qstat.qs_flags&C.FS_QUOTA_PDQ_ACCT > 0 {
		return extfsVolumeQuota{backingDev, mountpoint}
	}
	return nil
}

type extfsVolumeQuota struct {
	backingDev string
	mountpoint string
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

// GetQuotaOnDir -- get the quota ID that applies to this directory.
func (v extfsVolumeQuota) GetQuotaOnDir(path string) (common.QuotaID, error) {
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
	if fsx.fsx_projid == 0 {
		return common.BadQuotaID, fmt.Errorf("Failed to get quota ID for %s: %s", path, "no applicable quota")
	}
	return common.QuotaID(fsx.fsx_projid), nil
}

// ASetQuotaOnDir -- npply the specified quota to the directory.  If
// bytes is not greater than zero, the quota should be applied in a
// way that is non-enforcing (either explicitly so or by setting a
// quota larger than anything the user may possibly create)
func (v extfsVolumeQuota) SetQuotaOnDir(path string, id common.QuotaID, bytes int64) error {
	klog.V(3).Infof("xfsSetQuotaOn %s ID %v bytes %v", path, id, bytes)
	if bytes < 0 || bytes > maxQuota {
		bytes = maxQuota
	}

	var d C.struct_if_dqblk

	d.dqb_bhardlimit = C.__u64(bytes / quotaBsize)
	d.dqb_bsoftlimit = d.dqb_bhardlimit
	d.dqb_ihardlimit = 0
	d.dqb_isoftlimit = 0
	d.dqb_valid = C.QIF_LIMITS

	var cs = C.CString(v.backingDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, C.Q_SETPQUOTA,
		uintptr(unsafe.Pointer(cs)), uintptr(id),
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

func (v extfsVolumeQuota) getQuotaInfo(path string, id common.QuotaID) (C.struct_if_dqblk, syscall.Errno) {
	var d C.struct_if_dqblk

	var cs = C.CString(v.backingDev)
	defer C.free(unsafe.Pointer(cs))

	_, _, errno := unix.Syscall6(unix.SYS_QUOTACTL, C.Q_GETPQUOTA,
		uintptr(unsafe.Pointer(cs)), uintptr(C.__u32(id)),
		uintptr(unsafe.Pointer(&d)), 0, 0)
	return d, errno
}

// QuotaIDIsInUse -- determine whether the quota ID is already in use.
func (v extfsVolumeQuota) QuotaIDIsInUse(path string, id common.QuotaID) (bool, error) {
	d, errno := v.getQuotaInfo(path, id)
	isInUse := !(d.dqb_bhardlimit == 0 && d.dqb_bsoftlimit == 0 && d.dqb_curspace == 0 &&
		d.dqb_ihardlimit == 0 && d.dqb_isoftlimit == 0 && d.dqb_curinodes == 0 &&
		d.dqb_btime == 0 && d.dqb_itime == 0)
	return errno == 0 && isInUse, nil
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
// Note that with ext[[:digit:]]fs the quota consumption is in bytes
// per man quotactl
func (v extfsVolumeQuota) GetConsumption(path string, id common.QuotaID) (int64, error) {
	d, errno := v.getQuotaInfo(path, id)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get quota for %s: %s", path, errno.Error())
	}

	klog.V(3).Infof("Consumption for %s is %v", path, d.dqb_curspace)
	return int64(d.dqb_curspace), nil
}

// GetInodes -- retrieve the number of inodes in use under the directory
func (v extfsVolumeQuota) GetInodes(path string, id common.QuotaID) (int64, error) {
	d, errno := v.getQuotaInfo(path, id)
	if errno != 0 {
		return 0, fmt.Errorf("Failed to get quota for %s: %s", path, errno.Error())
	}
	klog.V(3).Infof("Inode consumption for %s is %v", path, d.dqb_curinodes)
	return int64(d.dqb_curinodes), nil
}
