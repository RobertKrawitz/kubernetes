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

import (
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/volume/util/quota/common"
)

//  ext4fs empirically has a maximum quota size of 2^48 - 1 1KiB blocks (256 petabytes)
const (
	linuxExtfsMagic       = 0xef53
	bitsPerWord           = 32 << (^uint(0) >> 63)                 // either 32 or 64
	maxQuota        int64 = (1<<(bitsPerWord-1) - 1) & (1<<58 - 1) // either 1<<31 - 1 or 1<<58 - 1
)

// VolumeProvider supplies a quota applier to the generic code.
type VolumeProvider struct {
}

// GetQuotaApplier -- does this backing device support quotas that
// can be applied to directories?
func (*VolumeProvider) GetQuotaApplier(mountpoint string, backingDev string) common.LinuxVolumeQuotaApplier {
	klog.V(3).Infof(">>>GetQuotaApplier extfs %s %s", mountpoint, backingDev)
	if common.IsFilesystemOfType(mountpoint, backingDev, linuxExtfsMagic) {
		klog.V(3).Infof("Yup")
		return extfsVolumeQuota{mountpoint, backingDev}
	}
	klog.V(3).Infof("No")
	return nil
}

type extfsVolumeQuota struct {
	mountpoint string
	backingDev string
}

// GetQuotaOnDir -- get the quota ID that applies to this directory.

func (v extfsVolumeQuota) GetQuotaOnDir(path string) (common.QuotaID, error) {
	klog.V(3).Infof(">>>GetQuotaOnDir extfs %s", path)
	return common.GetQuotaOnDir(path)
}

// SetQuotaOnDir -- apply the specified quota to the directory.  If
// bytes is not greater than zero, the quota should be applied in a
// way that is non-enforcing (either explicitly so or by setting a
// quota larger than anything the user may possibly create)
func (v extfsVolumeQuota) SetQuotaOnDir(path string, id common.QuotaID, bytes int64) error {
	klog.V(3).Infof("extfsSetQuotaOn %s ID %v bytes %v", path, id, bytes)
	if bytes < 0 || bytes > maxQuota {
		bytes = maxQuota
	}
	return common.SetQuotaOnDir(path, v.mountpoint, id, bytes)
}

// QuotaIDIsInUse -- determine whether the quota ID is already in use.
func (v extfsVolumeQuota) QuotaIDIsInUse(path string, id common.QuotaID) (bool, error) {
	klog.V(3).Infof(">>>QuotaIDIsInUse extfs %s %v", path, id)
	return common.QuotaIDIsInUse(v.mountpoint, id)
}

// GetConsumption -- retrieve the consumption (in bytes) of the directory
// Note that with ext[[:digit:]]fs the quota consumption is in bytes
// per man quotactl
func (v extfsVolumeQuota) GetConsumption(path string, id common.QuotaID) (int64, error) {
	klog.V(3).Infof(">>>GetConsumption extfs %s %v", path, id)
	return common.GetConsumption(v.mountpoint, id)
}

// GetInodes -- retrieve the number of inodes in use under the directory
func (v extfsVolumeQuota) GetInodes(path string, id common.QuotaID) (int64, error) {
	klog.V(3).Infof(">>>GetInodes extfs %s %v", path, id)
	return common.GetInodes(v.mountpoint, id)
}
