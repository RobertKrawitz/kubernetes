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
	"k8s.io/kubernetes/pkg/util/mount"
)

type QuotaID int32

const (
	BadQuota QuotaID = 0
)

type Interface interface {
	// Does the path provided support quotas, and if so, what types
	SupportsQuotas(m mount.Interface, path string) (bool, error)
	// Assign a quota (picked by the quota mechanism) to a path,
	// and return it.
	AssignQuota(m mount.Interface, path string, poduid string, bytes int64) (QuotaID, error)
	// Get the quota ID if any assigned to a path
	GetQuotaID(path string) (QuotaID, error)

	// Get the quota-based storage consumption for the path
	GetConsumption(path string) (int64, error)

	// Get the quota-based inode consumption for the path
	GetInodes(path string) (int64, error)

	// Remove the quota from a path
	// Implementations may assume that any data covered by the
	// quota has already been removed.
	ClearQuota(path string, poduid string) (error)
}
