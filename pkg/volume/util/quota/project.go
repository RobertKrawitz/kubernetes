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
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/volume/util/quota/common"
)

var projectsFile = "/etc/projects"
var projidFile = "/etc/projid"

var projectsParseRegexp *regexp.Regexp = regexp.MustCompilePOSIX("^([[:digit:]]+):")
var projidParseRegexp *regexp.Regexp = regexp.MustCompilePOSIX("[^#]:([[:digit:]]+)$")

var quotaIDLock sync.RWMutex

func projFilesAreOK() error {
	sProjects, err := os.Lstat(projectsFile)
	if err == nil && !sProjects.Mode().IsRegular() {
		return fmt.Errorf("%s exists but is not a plain file, cannot continue", projectsFile)
	}
	sProjid, err := os.Lstat(projidFile)
	if err == nil && !sProjid.Mode().IsRegular() {
		return fmt.Errorf("%s exists but is not a plain file, cannot continue", projidFile)
	}
	return nil
}

func lockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX)
}

func unlockFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}

// openAndLockProjectFiles opens /etc/projects and /etc/projid locked.
// Creates them if they don't exist
func openAndLockProjectFiles() (*os.File, *os.File, error) {
	// Make sure neither project-related file is a symlink!
	if err := projFilesAreOK(); err != nil {
		return nil, nil, err
	}
	fProjects, err := os.OpenFile(projectsFile, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, nil, err
	}
	fProjid, err := os.OpenFile(projidFile, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		fProjects.Close()
		return nil, nil, err
	}
	// ...and check once more!
	if err := projFilesAreOK(); err != nil {
		fProjid.Close()
		fProjects.Close()
		return nil, nil, err
	}
	err = lockFile(fProjects)
	if err != nil {
		fProjid.Close()
		fProjects.Close()
		return nil, nil, err
	}
	err = lockFile(fProjid)
	if err != nil {
		// Nothing useful we can do if we get an error here
		unlockFile(fProjects)
		fProjid.Close()
		fProjects.Close()
		return nil, nil, err
	}
	return fProjects, fProjid, nil
}

func closeProjectFiles(fProjects *os.File, fProjid *os.File) error {
	// Nothing useful we can do if either of these fail,
	// but we have to unlock and close the files anyway.
	// Do it in reverse order of locking, of course.
	var err error
	var err1 error
	if fProjid != nil {
		unlockFile(fProjid)
		err = fProjid.Close()
	}
	if fProjects != nil {
		unlockFile(fProjects)
		err1 = fProjects.Close()
	}
	if err != nil {
		return err
	}
	if err1 != nil {
		return err1
	}
	return nil
}

func scanOneFile(ifile *os.File, ofile *os.File, path string, idToRemove common.QuotaID, re *regexp.Regexp, idMap map[common.QuotaID]bool) error {
	scanner := bufio.NewScanner(ifile)
	foundIDToRemove := (idToRemove == common.BadQuotaID)
	for scanner.Scan() {
		rewriteLine := true
		match := re.FindStringSubmatch(scanner.Text())
		if match != nil {
			projid := match[1]
			i, err := strconv.Atoi(projid)
			id := common.QuotaID(i)
			if err != nil {
				klog.V(3).Infof("Couldn't parse projid %s: %#+v", projid, err)
				return err
			}
			if id == idToRemove && idToRemove != common.BadQuotaID {
				rewriteLine = false
				foundIDToRemove = true
			}
			if idToRemove == common.BadQuotaID {
				idMap[id] = true
			}
		}
		if rewriteLine {
			if _, err := ofile.WriteString(fmt.Sprintf("%s\n", scanner.Text())); err != nil {
				klog.V(3).Infof("Couldn't rewrite string: %#+v", err)
				return err
			}
		}
	}
	if scanner.Err() != nil {
		klog.V(3).Infof("Got error from scanner: %#+v", scanner.Err())
		return scanner.Err()
	}
	if !foundIDToRemove {
		klog.V(3).Infof("Couldn't find ID to remove")
		return fmt.Errorf("Cannot find project %v", idToRemove)
	}
	return nil
}

func findAvailableQuota(path string, idMap map[common.QuotaID]bool) (common.QuotaID, error) {
	for id := common.FirstQuota; id == id; id++ {
		if _, ok := idMap[id]; !ok {
			isInUse, err := dirApplierMap[path].QuotaIDIsInUse(path, id)
			if err != nil {
				return common.BadQuotaID, err
			} else if !isInUse {
				return id, nil
			}
		}
	}
	return common.BadQuotaID, nil
}

func scanProjectFilesInternal(projectsFile *os.File, projidFile *os.File, tmpProjectsFile *os.File, tmpProjidFile *os.File, path string, idToRemove common.QuotaID, idMap map[common.QuotaID]bool) (common.QuotaID, error) {
	var err error
	if err = scanOneFile(projectsFile, tmpProjectsFile, path, idToRemove, projectsParseRegexp, idMap); err != nil {
		klog.V(3).Infof("scanOneFile projects file failed %#+v", err)
		return common.BadQuotaID, err
	}
	if err = scanOneFile(projidFile, tmpProjidFile, path, idToRemove, projidParseRegexp, idMap); err != nil {
		klog.V(3).Infof("scanOneFile projid file failed %#+v", err)
		return common.BadQuotaID, err
	}
	id := common.BadQuotaID
	if idToRemove == common.BadQuotaID {
		// Add quota case: find a new quota and add it
		id, err = findAvailableQuota(path, idMap)
		klog.V(3).Infof("Got ID %v, err %v", id, err)
		if err == nil {
			_, err = tmpProjectsFile.WriteString(fmt.Sprintf("%v:%s\n", id, path))
			if err == nil {
				_, err = tmpProjidFile.WriteString(fmt.Sprintf("volume%v:%v\n", id, id))
			}
		}
		if err != nil {
			return common.BadQuotaID, err
		}
	}
	return id, nil
}

// If idToRemove is BadQuotaID, treat this as an add
// operation.  Too much of this code is in common not to share it.
// Returns the quota ID either removed or created.
// If removing an ID, the path is ignored.
func scanProjectFiles(fProjects *os.File, fProjid *os.File, path string, idToRemove common.QuotaID) (common.QuotaID, error) {
	projectsStat, err := fProjects.Stat()
	if err != nil {
		return common.BadQuotaID, err
	}
	projectsMode := projectsStat.Mode() & os.ModePerm
	projidStat, err := fProjid.Stat()
	if err != nil {
		return common.BadQuotaID, err
	}
	projidMode := projidStat.Mode() & os.ModePerm
	idMap := make(map[common.QuotaID]bool)
	tmpProjectsFile, err := ioutil.TempFile(filepath.Dir(projectsFile), filepath.Base(projectsFile))
	if err != nil {
		return common.BadQuotaID, err
	}
	tmpProjects := tmpProjectsFile.Name()
	tmpProjidFile, err := ioutil.TempFile(filepath.Dir(projidFile), filepath.Base(projidFile))
	if err != nil {
		tmpProjectsFile.Close()
		os.Remove(tmpProjects)
		return common.BadQuotaID, err
	}
	tmpProjid := tmpProjidFile.Name()
	id, err := scanProjectFilesInternal(fProjects, fProjid, tmpProjectsFile, tmpProjidFile, path, idToRemove, idMap)
	if err != nil {
		tmpProjectsFile.Close()
		os.Remove(tmpProjects)
		tmpProjidFile.Close()
		os.Remove(tmpProjid)
		return common.BadQuotaID, err
	}

	// Now, close the two files, rename new to old, and we're done.
	var errs [4]error
	errs[0] = tmpProjectsFile.Chmod(projectsMode)
	errs[1] = tmpProjectsFile.Close()
	errs[2] = tmpProjidFile.Chmod(projidMode)
	errs[3] = tmpProjidFile.Close()
	for _, err := range errs {
		if err != nil {
			os.Remove(tmpProjects)
			os.Remove(tmpProjid)
			return common.BadQuotaID, err
		}
	}
	// Until now everything has been safe; we've been working with temporary
	// files.  Now comes the dangerous part: renaming the two temporary
	// files over the old ones.  The first one's not too dangerous; if
	// the rename fails, we'll still have the old projid file.
	err = os.Rename(tmpProjid, projidFile)
	if err != nil {
		os.Remove(tmpProjid)
		os.Remove(tmpProjects)
		return common.BadQuotaID, err
	}
	// If *this* fails, the projects and projid files may be inconsistent.
	// Unfortunately, we can't atomically rename two files.
	err = os.Rename(tmpProjects, projectsFile)
	if err != nil {
		os.Remove(tmpProjects)
		return common.BadQuotaID, err
	}
	return id, nil
}

/*
func addDirToQuota(path string, id common.QuotaID) error {
	quotaIDLock.Lock()
	quotaIDLock.Unlock()
	return err
}

func removeDirFromQuota(path string, id common.QuotaID) error {
	quotaIDLock.Lock()
	quotaIDLock.Unlock()
	return err
}
*/

func createQuotaIDInternal(path string) (common.QuotaID, error) {
	fProjects, fProjid, err := openAndLockProjectFiles()
	klog.V(3).Infof(">>>>> openAndLockProjectFiles gives %v, %v, %v", fProjects, fProjid, err)
	if err != nil {
		return common.BadQuotaID, err
	}
	defer closeProjectFiles(fProjects, fProjid)
	ID, err := scanProjectFiles(fProjects, fProjid, path, common.BadQuotaID)
	if err != nil {
		return common.BadQuotaID, err
	}
	return ID, nil
}

func createQuotaID(path string) (common.QuotaID, error) {
	quotaIDLock.Lock()
	ID, err := createQuotaIDInternal(path)
	quotaIDLock.Unlock()
	return ID, err
}

func removeQuotaIDInternal(ID common.QuotaID) error {
	fProjects, fProjid, err := openAndLockProjectFiles()
	if err != nil {
		return err
	}
	defer closeProjectFiles(fProjects, fProjid)
	_, err = scanProjectFiles(fProjects, fProjid, "", ID)
	return err
}

func removeQuotaID(ID common.QuotaID) error {
	klog.V(3).Infof("<<<<< Removing quota %v", ID)
	quotaIDLock.Lock()
	err := removeQuotaIDInternal(ID)
	quotaIDLock.Unlock()
	return err
}
