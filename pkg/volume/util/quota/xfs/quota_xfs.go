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

import (
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/volume/util/quota/common"
)

const (
	linuxXfsMagic       = 0x58465342
	bitsPerWord         = 32 << (^uint(0) >> 63) // either 32 or 64
	maxQuota      int64 = 1<<(bitsPerWord-1) - 1 // either 1<<31 - 1 or 1<<63 - 1
)

// VolumeProvider supplies a quota applier to the generic code.
type VolumeProvider struct {
}

// GetQuotaApplier -- does this backing device support quotas that
// can be applied to directories?
func (*VolumeProvider) GetQuotaApplier(mountpoint string, backingDev string) common.LinuxVolumeQuotaApplier {
	if common.IsFilesystemOfType(mountpoint, backingDev, linuxXfsMagic) {
		return xfsVolumeQuota{mountpoint, backingDev}
	}
	return nil
}

type xfsVolumeQuota struct {
	mountpoint string
	backingDev string
}

// GetQuotaOnDir -- get the quota ID that applies to this directory.
func (v xfsVolumeQuota) GetQuotaOnDir(path string) (common.QuotaID, error) {
	return common.GetQuotaOnDir(path)
}

// SetQuotaOnDir -- apply the specified quota to the directory.  If
// bytes is not greater than zero, the quota should be applied in a
// way that is non-enforcing (either explicitly so or by setting a
// quota larger than anything the user may possibly create)
func (v xfsVolumeQuota) SetQuotaOnDir(path string, id common.QuotaID, bytes int64) error {
	klog.V(3).Infof("xfsSetQuotaOn %s ID %v bytes %v", path, id, bytes)
	if bytes < 0 || bytes > maxQuota {
		bytes = maxQuota
	}
	return common.SetQuotaOnDir(path, v.mountpoint, id, bytes)
}

// QuotaIDIsInUse -- determine whether the quota ID is already in use.
func (v xfsVolumeQuota) QuotaIDIsInUse(path string, id common.QuotaID) (bool, error) {
	return common.QuotaIDIsInUse(v.mountpoint, id)
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
func (v xfsVolumeQuota) GetConsumption(path string, id common.QuotaID) (int64, error) {
	return common.GetConsumption(v.mountpoint, id)
}

// GetInodes -- retrieve the number of inodes in use under the directory
func (v xfsVolumeQuota) GetInodes(path string, id common.QuotaID) (int64, error) {
	return common.GetInodes(v.mountpoint, id)
}
