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

var projectsParseRegexp *regexp.Regexp = regexp.MustCompilePOSIX("^([[:digit:]]+):(.*)$")
var projidParseRegexp *regexp.Regexp = regexp.MustCompilePOSIX("^([^#][^:]*):([[:digit:]]+)$")

var quotaIDLock sync.RWMutex

type projectType struct {
	isValid bool // False if we need to remove this line
	id      common.QuotaID
	data    string
	line    string
}

type projectsList struct {
	projects []projectType
	projid   []projectType
}

func projFilesAreOK() error {
	if sf, err := os.Lstat(projectsFile); err != nil || sf.Mode().IsRegular() {
		if sf, err := os.Lstat(projidFile); err != nil || sf.Mode().IsRegular() {
			return nil
		}
		return fmt.Errorf("%s exists but is not a plain file, cannot continue", projidFile)
	}
	return fmt.Errorf("%s exists but is not a plain file, cannot continue", projectsFile)
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
	// We don't actually modify the original files; we create temporaries and
	// move them over the originals
	fProjects, err := os.OpenFile(projectsFile, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, nil, err
	}
	fProjid, err := os.OpenFile(projidFile, os.O_RDONLY|os.O_CREATE, 0644)
	if err == nil {
		// Check once more, to ensure nothing got changed out from under us
		if err := projFilesAreOK(); err == nil {
			err = lockFile(fProjects)
			if err == nil {
				err = lockFile(fProjid)
				if err == nil {
					return fProjects, fProjid, nil
				}
				// Nothing useful we can do if we get an error here
				unlockFile(fProjects)
			}
		}
		fProjid.Close()
	}
	fProjects.Close()
	return nil, nil, err
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

func parseProject(l string) projectType {
	match := projectsParseRegexp.FindStringSubmatch(l)
	if match != nil {
		i, err := strconv.Atoi(match[1])
		if err == nil {
			return projectType{true, common.QuotaID(i), match[2], l}
		}
	}
	return projectType{true, common.BadQuotaID, "", l}
}

func parseProjectsFile(f *os.File) []projectType {
	var projects []projectType
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		project := parseProject(scanner.Text())
		projects = append(projects, project)
	}
	return projects
}

func parseProjid(l string) projectType {
	match := projidParseRegexp.FindStringSubmatch(l)
	if match != nil {
		i, err := strconv.Atoi(match[2])
		if err == nil {
			return projectType{true, common.QuotaID(i), match[1], l}
		}
	}
	return projectType{true, common.BadQuotaID, "", l}
}

func parseProjidFile(f *os.File) []projectType {
	var projids []projectType
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		projid := parseProjid(scanner.Text())
		projids = append(projids, projid)
	}
	return projids
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
	return common.BadQuotaID, fmt.Errorf("Cannot find available quota ID")
}

func addDirToProject(path string, id common.QuotaID, list *projectsList) (common.QuotaID, error) {
	idMap := make(map[common.QuotaID]bool)
	for _, project := range list.projects {
		if project.data == path {
			if id != project.id {
				return common.BadQuotaID, fmt.Errorf("Attempt to reassign project ID for %s", path)
			}
			// Trying to reassign a directory to the project it's
			// already in.  Maybe this should be an error, but for
			// now treat it as an idempotent operation
			return id, nil
		}
		idMap[project.id] = true
	}
	var needToAddProjid = true
	for _, projid := range list.projid {
		idMap[projid.id] = true
		if projid.id == id && id != common.BadQuotaID {
			needToAddProjid = false
		}
	}
	var err error
	if id == common.BadQuotaID {
		id, err = findAvailableQuota(path, idMap)
		if err != nil {
			return common.BadQuotaID, err
		}
		needToAddProjid = true
	}
	if needToAddProjid {
		name := fmt.Sprintf("volume%v", id)
		line := fmt.Sprintf("%s:%v", name, id)
		list.projid = append(list.projid, projectType{true, id, name, line})
	}
	line := fmt.Sprintf("%v:%s", id, path)
	list.projects = append(list.projects, projectType{true, id, path, line})
	return id, nil
}

func removeDirFromProject(path string, id common.QuotaID, list *projectsList) error {
	if id == common.BadQuotaID {
		return fmt.Errorf("Attempt to remove invalid quota ID from %s", path)
	}
	foundAt := -1
	countByID := make(map[common.QuotaID]int)
	for i, project := range list.projects {
		if project.data == path {
			if id != project.id {
				return fmt.Errorf("Attempting to remove quota ID %v from path %s, but expecting ID %v", id, path, project.id)
			} else if foundAt != -1 {
				return fmt.Errorf("Found multiple quota IDs for path %s", path)
			}
			// Faster and easier than deleting an element
			list.projects[i].isValid = false
			foundAt = i
		}
		countByID[project.id]++
	}
	if foundAt == -1 {
		return fmt.Errorf("Cannot find quota associated with path %s", path)
	}
	if countByID[id] <= 1 {
		// Removing the last entry means that we're no longer using
		// the quota ID, so remove that as well
		for i, projid := range list.projid {
			if projid.id == id {
				list.projid[i].isValid = false
			}
		}
	}
	return nil
}

func readProjectFiles(projects *os.File, projid *os.File) projectsList {
	return projectsList{parseProjectsFile(projects), parseProjidFile(projid)}
}

func writeProjectFile(base *os.File, projects []projectType) (string, error) {
	oname := base.Name()
	stat, err := base.Stat()
	if err != nil {
		return "", err
	}
	mode := stat.Mode() & os.ModePerm
	f, err := ioutil.TempFile(filepath.Dir(oname), filepath.Base(oname))
	if err != nil {
		return "", err
	}
	filename := f.Name()
	if err := os.Chmod(filename, mode); err != nil {
		return "", err
	}
	for _, proj := range projects {
		if proj.isValid {
			if _, err := f.WriteString(fmt.Sprintf("%s\n", proj.line)); err != nil {
				f.Close()
				os.Remove(filename)
				return "", err
			}
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(filename)
		return "", err
	}
	return filename, nil
}

func writeProjectFiles(fProjects *os.File, fProjid *os.File, list projectsList) error {
	tmpProjid, err := writeProjectFile(fProjid, list.projid)
	if err != nil {
		return err
	}
	tmpProjects, err := writeProjectFile(fProjects, list.projects)
	if err == nil {
		err = os.Rename(tmpProjid, fProjid.Name())
		// Until now everything has been safe; we've been working with temporary
		// files.  Now comes the dangerous part: renaming the two temporary
		// files over the old ones.  The first one's not too dangerous; if
		// the rename fails, we'll still have the old projid file.
		if err == nil {
			err = os.Rename(tmpProjects, fProjects.Name())
			if err == nil {
				return nil
			}
		}
		os.Remove(tmpProjects)
	}
	os.Remove(tmpProjid)
	klog.V(3).Infof("Unable to write project files: %v", err)
	return err
}

func createQuotaID(path string) (common.QuotaID, error) {
	quotaIDLock.Lock()
	defer quotaIDLock.Unlock()
	fProjects, fProjid, err := openAndLockProjectFiles()
	ID := common.BadQuotaID
	if err == nil {
		defer closeProjectFiles(fProjects, fProjid)
		list := readProjectFiles(fProjects, fProjid)
		ID, err = addDirToProject(path, common.BadQuotaID, &list)
		if err == nil && ID != common.BadQuotaID {
			if err = writeProjectFiles(fProjects, fProjid, list); err == nil {
				return ID, nil
			}
		}
	}
	klog.V(3).Infof("addQuotaID %s %v failed %v", path, ID, err)
	return common.BadQuotaID, err
}

func removeQuotaID(path string, ID common.QuotaID) error {
	if ID == common.BadQuotaID {
		return fmt.Errorf("attempting to remove invalid quota ID %v", ID)
	}
	quotaIDLock.Lock()
	defer quotaIDLock.Unlock()
	fProjects, fProjid, err := openAndLockProjectFiles()
	if err == nil {
		defer closeProjectFiles(fProjects, fProjid)
		list := readProjectFiles(fProjects, fProjid)
		err = removeDirFromProject(path, ID, &list)
		if err == nil {
			if err = writeProjectFiles(fProjects, fProjid, list); err == nil {
				return nil
			}
		}
	}
	klog.V(3).Infof("removeQuotaID %s %v failed %v", path, ID, err)
	return err
}
