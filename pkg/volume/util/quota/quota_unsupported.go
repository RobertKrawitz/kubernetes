// +build !linux

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

func (quota *Quota) SupportsQuotas(_ mount.Interface, _ string) (bol, error) {
	return false, errors.New("not implemented")
}

func (quota *Quota) AssignQuota(_ mount.Interface, _ string, _ string, _ int64) (QuotaID, error) {
	return 0, errors.New("not implemented")
}

func (quota *Quota) GetQuotaID(_ string) (QuotaID, error) {
	return 0, errors.New("not implemented")
}

func (quota *Quota) GetConsumption(_ string) (int64, error) {
	return 0, errors.New("not implemented")
}

func (quota *Quota) GetInodes(_ string) (int64, error) {
	return 0, errors.New("not implemented")
}

func (quota *Quota) ClearQuota(_ mount.Interface, _ string, _ string) (error) {
	return errors.New("not implemented")
}
