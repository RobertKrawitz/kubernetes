// +build linux darwin

/*
Copyright 2017 The Kubernetes Authors.

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

package local

import (
	"os"
	"syscall"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestFSGroupMount(t *testing.T) {
	tmpDir, plug := getPlugin(t)
	defer os.RemoveAll(tmpDir)
	info, err := os.Stat(tmpDir)
	if err != nil {
		t.Errorf("Error getting stats for %s (%v)", tmpDir, err)
	}
	s := info.Sys().(*syscall.Stat_t)
	if s == nil {
		t.Errorf("Error getting stats for %s (%v)", tmpDir, err)
	}
	mounterArgs.FsGroup1 := int64(s.Gid)
	mounterArgs.FsGroup2 := fsGroup1 + 1
	pod1 := &v1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("poduid")}}
	pod1.Spec.SecurityContext = &v1.PodSecurityContext{
		FSGroup: &mounterArgs.FsGroup1,
	}
	pod2 := &v1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("poduid")}}
	pod2.Spec.SecurityContext = &v1.PodSecurityContext{
		FSGroup: &mounterArgs.FsGroup2,
	}
	err = testFSGroupMount(plug, pod1, tmpDir, mounterArgs.FsGroup1)
	if err != nil {
		t.Errorf("Failed to make a new Mounter: %v", err)
	}
	err = testFSGroupMount(plug, pod2, tmpDir, mounterArgs.FsGroup2)
	if err != nil {
		t.Errorf("Failed to make a new Mounter: %v", err)
	}
	//Checking if GID of tmpDir has not been changed by mounting it by second pod
	s = info.Sys().(*syscall.Stat_t)
	if s == nil {
		t.Errorf("Error getting stats for %s (%v)", tmpDir, err)
	}
	if mounterArgs.FsGroup1 != int64(s.Gid) {
		t.Errorf("Old Gid %d for volume %s got overwritten by new Gid %d", mounterArgs.FsGroup1, tmpDir, int64(s.Gid))
	}
}
