// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package virtrun

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aibor/virtrun/internal/virtfs"
)

type nameFunc func(idx int, path string) string

func baseName(_ int, path string) string {
	return filepath.Base(path)
}

func modName(idx int, path string) string {
	return fmt.Sprintf("%04d-%s", idx, filepath.Base(path))
}

type fsBuilder struct {
	fs virtfs.FSAdder
}

func (b *fsBuilder) mkdirAll(dir string) error {
	return b.fs.MkdirAll(dir) //nolint:wrapcheck
}

func (b *fsBuilder) add(name string, openFn virtfs.FileOpenFunc) error {
	return b.fs.Add(name, openFn) //nolint:wrapcheck
}

func (b *fsBuilder) symlink(target, name string) error {
	return b.fs.Symlink(target, name) //nolint:wrapcheck
}

func (b *fsBuilder) addFilePathAs(name, source string) error {
	return b.add(name, func() (fs.File, error) {
		return os.Open(source)
	})
}

func (b *fsBuilder) addFilesTo(dir string, files []string, fn nameFunc) error {
	err := b.mkdirAll(dir)
	if err != nil {
		return err
	}

	for idx, path := range files {
		name := filepath.Join(dir, fn(idx, path))

		err := b.addFilePathAs(name, path)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *fsBuilder) symlinkTo(dir string, paths []string) error {
	for _, path := range paths {
		if path == dir {
			continue
		}

		path := strings.TrimPrefix(path, string(filepath.Separator))
		if path == "" || path == dir {
			continue
		}

		err := b.mkdirAll(filepath.Dir(path))
		if err != nil {
			return err
		}

		err = b.symlink(libsDir, path)
		if err != nil {
			return err
		}
	}

	return nil
}
