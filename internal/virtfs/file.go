// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package virtfs

import (
	"io"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type file interface {
	open(entry dirEntry) (fs.File, error)
	mode() fs.FileMode
}

var (
	_ fs.FileInfo = (*fileInfo)(nil)
	_ fs.DirEntry = (*fileInfo)(nil)
	_ fs.DirEntry = (*dirEntry)(nil)
)

type dirEntry struct {
	name string
	file file
}

func (e *dirEntry) Name() string      { return filepath.Base(e.name) }
func (e *dirEntry) Type() fs.FileMode { return e.file.mode().Type() }
func (e *dirEntry) IsDir() bool       { return e.file.mode()&fs.ModeDir != 0 }
func (e *dirEntry) String() string    { return fs.FormatDirEntry(e) }

func (e *dirEntry) Info() (fs.FileInfo, error) {
	file, err := e.file.open(*e)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return file.Stat() //nolint:wrapcheck
}

type fileInfo struct {
	dirEntry
	size int64
}

func (i *fileInfo) Size() int64       { return i.size }
func (i *fileInfo) Mode() fs.FileMode { return i.file.mode() }
func (*fileInfo) ModTime() time.Time  { return time.Time{} }
func (i *fileInfo) Sys() any          { return i.file }
func (i *fileInfo) String() string    { return fs.FormatFileInfo(i) }

var (
	_ fs.File        = (*openFile)(nil)
	_ fs.ReadDirFile = (*openFile)(nil)
)

type openFile struct {
	info    fileInfo
	reader  io.Reader
	entries []fs.DirEntry
	offset  int
}

// Stat implements [fs.File].
func (f *openFile) Stat() (fs.FileInfo, error) {
	return &f.info, nil
}

// Read implements [fs.File].
func (f *openFile) Read(b []byte) (int, error) {
	if f.reader == nil {
		return 0, ErrFileInvalid
	}

	return f.reader.Read(b) //nolint:wrapcheck
}

// Close implements [fs.File].
func (f *openFile) Close() error {
	closer, ok := f.reader.(io.Closer)
	if !ok {
		return nil
	}

	return closer.Close() //nolint:wrapcheck
}

// ReadDir implements [fs.ReadDirFile].
func (f *openFile) ReadDir(count int) ([]fs.DirEntry, error) {
	if !f.info.IsDir() {
		return nil, ErrFileNotDir
	}

	start := f.offset
	end := len(f.entries)
	available := end - start

	if available == 0 && count > 0 {
		return nil, io.EOF
	}

	if count > 0 && available > count {
		end = start + count
	}

	f.offset = end

	return f.entries[start:end], nil
}

var _ file = (*regularFile)(nil)

type regularFile FileOpenFunc

func (regularFile) mode() fs.FileMode {
	return defaultFileMode
}

func (f regularFile) open(info dirEntry) (fs.File, error) {
	file, err := f()
	if err != nil {
		return nil, err
	}

	sourceInfo, err := file.Stat()
	if err != nil {
		return nil, err //nolint:wrapcheck
	}

	if !sourceInfo.Mode().IsRegular() {
		return nil, ErrFileNotRegular
	}

	o := &openFile{
		info: fileInfo{
			dirEntry: info,
			size:     sourceInfo.Size(),
		},
		reader: file,
	}

	return o, nil
}

var _ file = (*symbolicLink)(nil)

type symbolicLink string

func (symbolicLink) mode() fs.FileMode {
	return defaultFileMode | fs.ModeSymlink
}

func (l symbolicLink) open(info dirEntry) (fs.File, error) {
	reader := strings.NewReader(string(l))

	o := &openFile{
		info: fileInfo{
			dirEntry: info,
			size:     reader.Size(),
		},
		reader: reader,
	}

	return o, nil
}

var _ file = (*directory)(nil)

type directory map[string]file

func (*directory) mode() fs.FileMode {
	return defaultFileMode | fs.ModeDir
}

func (d *directory) open(info dirEntry) (fs.File, error) {
	o := &openFile{
		info: fileInfo{
			dirEntry: info,
		},
		entries: d.entries(),
	}

	return o, nil
}

func (d *directory) entries() []fs.DirEntry {
	entries := make([]fs.DirEntry, 0, len(*d))

	for _, name := range slices.Sorted(maps.Keys(*d)) {
		entries = append(entries, &dirEntry{
			name: name,
			file: (*d)[name],
		})
	}

	return entries
}

func (d *directory) add(name string, file file) error {
	if name == "." {
		return ErrFileExist
	}

	_, exists := (*d)[name]
	if exists {
		return ErrFileExist
	}

	(*d)[name] = file

	return nil
}
