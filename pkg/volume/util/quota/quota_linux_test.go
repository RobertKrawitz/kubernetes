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
	"io/ioutil"
	"k8s.io/kubernetes/pkg/util/mount"
	"os"
	"testing"
)

const dummyMountData = `sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=6133536k,nr_inodes=1533384,mode=755 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
/dev/sda1 /boot ext4 rw,relatime 0 0
/dev/mapper/fedora-root / ext4 rw,noatime 0 0
/dev/mapper/fedora-home /home ext4 rw,noatime 0 0
/dev/sdb1 /virt xfs rw,noatime,attr2,inode64,usrquota,prjquota 0 0
`

const dummyMountDataPquota = `tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
/dev/sda1 /boot ext4 rw,relatime 0 0
/dev/mapper/fedora-root / ext4 rw,noatime 0 0
/dev/mapper/fedora-home /home ext4 rw,noatime 0 0
/dev/sdb1 /mnt/virt xfs rw,noatime,attr2,inode64,usrquota,prjquota 0 0
`
const dummyMountDataNoPquota = `tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
/dev/sda1 /boot ext4 rw,relatime 0 0
/dev/mapper/fedora-root / ext4 rw,noatime 0 0
/dev/mapper/fedora-home /home ext4 rw,noatime 0 0
/dev/sdb1 /mnt/virt xfs rw,noatime,attr2,inode64,usrquota 0 0
`

func dummyFakeMount1() mount.Interface {
	return &mount.FakeMounter{
		MountPoints: []mount.MountPoint{
			{
				Device: "tmpfs",
				Path:   "/tmp",
				Type:   "tmpfs",
				Opts:   []string{"rw", "nosuid", "nodev"},
			},
			{
				Device: "/dev/sda1",
				Path:   "/boot",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "dev/mapper/fedora-root",
				Path:   "/",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "dev/mapper/fedora-home",
				Path:   "/home",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "/dev/sdb1",
				Path:   "/mnt/virt",
				Type:   "xfs",
				Opts:   []string{"rw", "relatime", "attr2", "inode64", "usrquota", "prjquota"},
			},
		},
	}
}

func dummyFakeMount2() mount.Interface {
	return &mount.FakeMounter{
		MountPoints: []mount.MountPoint{
			{
				Device: "tmpfs",
				Path:   "/tmp",
				Type:   "tmpfs",
				Opts:   []string{"rw", "nosuid", "nodev"},
			},
			{
				Device: "/dev/sda1",
				Path:   "/boot",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "dev/mapper/fedora-root",
				Path:   "/",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "dev/mapper/fedora-home",
				Path:   "/home",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "/dev/sdb1",
				Path:   "/mnt/virt",
				Type:   "xfs",
				Opts:   []string{"rw", "relatime", "attr2", "inode64", "usrquota", "pquota"},
			},
		},
	}
}

func dummyFakeMount3() mount.Interface {
	return &mount.FakeMounter{
		MountPoints: []mount.MountPoint{
			{
				Device: "tmpfs",
				Path:   "/tmp",
				Type:   "tmpfs",
				Opts:   []string{"rw", "nosuid", "nodev"},
			},
			{
				Device: "/dev/sda1",
				Path:   "/boot",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "dev/mapper/fedora-root",
				Path:   "/",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "dev/mapper/fedora-home",
				Path:   "/home",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "/dev/sdb1",
				Path:   "/mnt/virt",
				Type:   "xfs",
				Opts:   []string{"rw", "relatime", "attr2", "inode64", "usrquota", "pqnoenforce"},
			},
		},
	}
}

func dummyFakeMount4() mount.Interface {
	return &mount.FakeMounter{
		MountPoints: []mount.MountPoint{
			{
				Device: "tmpfs",
				Path:   "/tmp",
				Type:   "tmpfs",
				Opts:   []string{"rw", "nosuid", "nodev"},
			},
			{
				Device: "/dev/sda1",
				Path:   "/boot",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "/dev/mapper/fedora-root",
				Path:   "/",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "/dev/mapper/fedora-home",
				Path:   "/home",
				Type:   "ext4",
				Opts:   []string{"rw", "relatime"},
			},
			{
				Device: "/dev/sdb1",
				Path:   "/mnt/virt",
				Type:   "xfs",
				Opts:   []string{"rw", "relatime", "attr2", "inode64", "usrquota"},
			},
		},
	}
}

type backingDevTest struct {
	path           string
	mountdata      string
	expectedResult string
	expectFailure  bool
}

type mountpointTest struct {
	path           string
	mounter        mount.Interface
	expectedResult string
	expectFailure  bool
}

func testBackingDev1(testcase backingDevTest) error {
	tmpfile, err := ioutil.TempFile("", "backingdev")
	if err != nil {
		return err
	}
	defer os.Remove(tmpfile.Name())
	if _, err = tmpfile.WriteString(testcase.mountdata); err != nil {
		return err
	}

	backingDev, err := detectBackingDevInternal(testcase.path, tmpfile.Name())
	if err != nil {
		if testcase.expectFailure {
			return nil
		}
		return err
	}
	if testcase.expectFailure {
		return fmt.Errorf("Path %s expected to fail; succeeded and got %s", testcase.path, backingDev)
	}
	if backingDev == testcase.expectedResult {
		return nil
	}
	return fmt.Errorf("Mismatch: path %s expects mountpoint %s got %s", testcase.path, testcase.expectedResult, backingDev)
}

func TestBackingDev(t *testing.T) {
	testcasesBackingDev := map[string]backingDevTest{
		"Root": {
			"/",
			dummyMountData,
			"/dev/mapper/fedora-root",
			false,
		},
		"tmpfs": {
			"/tmp",
			dummyMountData,
			"tmpfs",
			false,
		},
		"user filesystem": {
			"/virt",
			dummyMountData,
			"/dev/sdb1",
			false,
		},
		"empty mountpoint": {
			"",
			dummyMountData,
			"",
			true,
		},
		"bad mountpoint": {
			"/kiusf",
			dummyMountData,
			"",
			true,
		},
	}
	for name, testcase := range testcasesBackingDev {
		err := testBackingDev1(testcase)
		if err != nil {
			t.Errorf("%s failed: %s", name, err.Error())
		}
	}
}

func TestDetectMountPoint(t *testing.T) {
	testcasesMount := map[string]mountpointTest{
		"Root": {
			"/",
			dummyFakeMount1(),
			"/",
			false,
		},
		"(empty)": {
			"",
			dummyFakeMount1(),
			"/",
			false,
		},
		"(invalid)": {
			"",
			dummyFakeMount1(),
			"/",
			false,
		},
		"/usr": {
			"/usr",
			dummyFakeMount1(),
			"/",
			false,
		},
		"/var/tmp": {
			"/var/tmp",
			dummyFakeMount1(),
			"/",
			false,
		},
	}
	for name, testcase := range testcasesMount {
		mountpoint, err := detectMountpointInternal(testcase.mounter, testcase.path)
		if err == nil && testcase.expectFailure {
			t.Errorf("Case %s expected failure, but succeeded, returning mountpoint %s", name, mountpoint)
		} else if err != nil {
			t.Errorf("Case %s failed: %s", name, err.Error())
		} else if mountpoint != testcase.expectedResult {
			t.Errorf("Case %s got mountpoint %s, expected %s", name, mountpoint, testcase.expectedResult)
		}
	}
}
