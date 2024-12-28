// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package virtfs

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

const (
	defaultFileMode = 0o755
	symlinkDepth    = 10
)

// FileOpenFunc returns an open [fs.File] or an error if opening fails.
type FileOpenFunc func() (fs.File, error)

// FSAdder defines the interface required to add files to a FS.
type FSAdder interface {
	Add(name string, openFn FileOpenFunc) error
	Symlink(oldname, newname string) error
	Mkdir(name string) error
	MkdirAll(name string) error
}

var (
	_ fs.FS      = (*FS)(nil)
	_ ReadLinkFS = (*FS)(nil)
	_ FSAdder    = (*FS)(nil)
)

// FS represents a simple [fs.FS] that supports directories, regular files and
// symbolic links
//
// Regular files that should be copied from another source can be added with
// [FS.Add].It supports adding symbolic links with [FS.Symlink]. Use [FS.Mkdir]
// or [FS.MkdirAll] to create any required directories beforehand.
type FS struct {
	root directory
}

// New creates a new [FS].
func New() *FS {
	return &FS{
		root: make(directory),
	}
}

// Open opens the named file.
//
// It returns a [PathError] in case of errors. It does not follow symbolic
// links and returns symbolic links directly.
func (fsys *FS) Open(name string) (fs.File, error) {
	file, err := fsys.open(name, true)
	if err != nil {
		return nil, &PathError{
			Op:   "open",
			Path: name,
			Err:  err,
		}
	}

	return file, nil
}

// ReadLink returns the target of the symbolic link with the given name.
//
// It returns a [PathError] in case of errors. It returns ErrFileInvalid in
// case the file is not a symbolic link.
func (fsys *FS) ReadLink(name string) (string, error) {
	target, err := fsys.readlink(name)
	if err != nil {
		return "", &PathError{
			Op:   "readlink",
			Path: name,
			Err:  err,
		}
	}

	return target, nil
}

// Lstat returns information about the file with the given name.
//
// It returns a [PathError] in case of errors. It does not follow symbolic
// links and returns symbolic links directly.
func (fsys *FS) Lstat(name string) (fs.FileInfo, error) {
	info, err := fsys.lstat(name)
	if err != nil {
		return nil, &PathError{
			Op:   "lstat",
			Path: name,
			Err:  err,
		}
	}

	return info, nil
}

// Mkdir creates a new directory with the given name.
//
// It returns [PathError] in case of errors.
func (fsys *FS) Mkdir(name string) error {
	parentName, dirName := filepath.Split(clean(name))

	parent, err := fsys.subDir(clean(parentName))
	if err != nil {
		return &PathError{
			Op:   "mkdir",
			Path: name,
			Err:  err,
		}
	}

	err = parent.add(dirName, &directory{})
	if err != nil {
		return &PathError{
			Op:   "mkdir",
			Path: name,
			Err:  err,
		}
	}

	return nil
}

// MkdirAll creates a directory with the given name along with all necessary
// parents.
//
// It returns a [PathError] in case of errors. If the directory exists already,
// it does nothing and returns nil.
func (fsys *FS) MkdirAll(name string) error {
	cleaned := clean(name)

	dEntry, err := fsys.find(cleaned, symlinkDepth)
	if err == nil {
		if dEntry.IsDir() {
			return nil
		}

		return &PathError{
			Op:   "mkdir",
			Path: name,
			Err:  ErrFileNotDir,
		}
	}

	parent := filepath.Dir(cleaned)
	if parent != cleaned {
		err = fsys.MkdirAll(parent)
		if err != nil {
			return err
		}
	}

	return fsys.Mkdir(name)
}

// Add creates a new regular file with the given name.
//
// File content is read from the file returned by the given [FileOpenFunc]. It
// returns a [PathError] in case of errors.
func (fsys *FS) Add(name string, openFn FileOpenFunc) error {
	if openFn == nil {
		return &PathError{
			Op:   "add",
			Path: name,
			Err:  fmt.Errorf("%w: openFunc is nil", ErrInvalidArgument),
		}
	}

	err := fsys.add(name, regularFile(openFn))
	if err != nil {
		return &PathError{
			Op:   "add",
			Path: name,
			Err:  err,
		}
	}

	return nil
}

// Symlink adds a new symbolic link that links to oldname at newname.
//
// It returns a [PathError] in case of errors.
func (fsys *FS) Symlink(oldname, newname string) error {
	file := symbolicLink(oldname)

	err := fsys.add(newname, file)
	if err != nil {
		return &PathError{
			Op:   "symlink",
			Path: newname,
			Err:  err,
		}
	}

	return nil
}

func (fsys *FS) subDir(name string) (*directory, error) {
	dEntry, err := fsys.find(name, symlinkDepth)
	if err != nil {
		return nil, err
	}

	dir, isDir := dEntry.file.(*directory)
	if !isDir {
		return nil, ErrFileNotDir
	}

	return dir, nil
}

func (fsys *FS) add(name string, file file) error {
	dirName, fileName := filepath.Split(clean(name))

	parent, err := fsys.subDir(clean(dirName))
	if err != nil {
		return err
	}

	err = parent.add(fileName, file)
	if err != nil {
		return err
	}

	return nil
}

func (fsys *FS) open(name string, follow bool) (fs.File, error) {
	findFn := fsys.findNoFollow
	if follow {
		findFn = fsys.find
	}

	dEntry, err := findFn(name, symlinkDepth)
	if err != nil {
		return nil, err
	}

	return dEntry.file.open(dEntry)
}

func (fsys *FS) readlink(name string) (string, error) {
	dEntry, err := fsys.findNoFollow(name, symlinkDepth)
	if err != nil {
		return "", err
	}

	symlink, isSymlink := dEntry.file.(symbolicLink)
	if !isSymlink {
		return "", ErrFileInvalid
	}

	return string(symlink), nil
}

func (fsys *FS) lstat(name string) (fs.FileInfo, error) {
	file, err := fsys.open(name, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err //nolint:wrapcheck
	}

	return info, nil
}

func (fsys *FS) find(name string, depth uint) (dirEntry, error) {
	dEntry, err := fsys.findNoFollow(name, depth)
	if err != nil {
		return dirEntry{}, err
	}

	return fsys.follow(dEntry, depth)
}

func (fsys *FS) findNoFollow(name string, depth uint) (dirEntry, error) {
	dEntry := dirEntry{name, &fsys.root}

	if name == "" || name == "." {
		return dEntry, nil
	}

	if !fs.ValidPath(name) {
		return dirEntry{}, ErrFileInvalid
	}

	nodes := strings.Split(name, string(filepath.Separator))
	for _, name = range nodes {
		var err error

		dEntry, err = fsys.follow(dEntry, depth)
		if err != nil {
			return dirEntry{}, err
		}

		if !dEntry.IsDir() {
			return dirEntry{}, ErrFileNotExist
		}

		next, exists := (*dEntry.file.(*directory))[name]
		if !exists {
			return dirEntry{}, ErrFileNotExist
		}

		dEntry = dirEntry{name, next}
	}

	return dEntry, nil
}

func (fsys *FS) follow(dEntry dirEntry, depth uint) (dirEntry, error) {
	symlink, isSymlink := dEntry.file.(symbolicLink)
	if !isSymlink {
		return dEntry, nil
	}

	if depth == 0 {
		return dirEntry{}, ErrSymlinkTooDeep
	}

	depth--

	return fsys.find(clean(string(symlink)), depth)
}

func clean(path string) string {
	path = filepath.Clean(path)
	return strings.TrimPrefix(path, string(filepath.Separator))
}
