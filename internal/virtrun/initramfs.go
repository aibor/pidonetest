// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package virtrun

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"

	"github.com/aibor/cpio"
	"github.com/aibor/virtrun/internal/sys"
	"github.com/aibor/virtrun/internal/virtfs"
)

const (
	dataDir    = "/data"
	libsDir    = "/lib"
	modulesDir = "/lib/modules"
)

type Initramfs struct {
	// Binary is the main binary that is either called directly or by the init
	// program depending on the StandaloneInit flag.
	Binary string

	// Files is a list of any additional files that should be added to the
	// dataDir directory. For ELF files the required dynamic libraries are
	// added the libsDir directory.
	Files []string

	// Modules is a list of kernel module files. They are added to the
	// modulesDir directory.
	Modules []string

	// StandaloneInit determines if the main Binary should be called as init
	// directly. The main binary is responsible for a clean shutdown of the
	// system.
	StandaloneInit bool

	// Keep determines if the archive file is removed by the cleanup function
	// returned by [BuildInitramfsArchive]. If set to true, the file is not
	// removed. Instead, a log message with the file's path is printed.
	Keep bool
}

// BuildInitramfsArchive creates a new initramfs CPIO archive file.
//
// The archive consists of a main binary that is either called directly or
// by the init program. All other files are added to the dataDir directory.
// Kernel modules are added to modulesDir directory. For all ELF files the
// dynamically linked shared objects are collected and added to the libsDir
// directory. The paths to the directories they have been found at are added as
// symlinks to the libsDir directory as well.
//
// The CPIO archive is written to [os.TempDir]. The path to the file is
// returned along with a cleanup function. The caller is responsible to call
// the function once the archive file is no longer needed.
func BuildInitramfsArchive(
	ctx context.Context,
	cfg Initramfs,
	initFileOpenFn virtfs.FileOpenFunc,
) (string, func() error, error) {
	fsys, err := buildInitramfsArchive(ctx, cfg, initFileOpenFn)
	if err != nil {
		return "", nil, err
	}

	path, err := writeFSToTempFile(fsys, "")
	if err != nil {
		return "", nil, err
	}

	slog.Debug("Created initramfs archive", slog.String("path", path))

	var removeFn func() error

	if cfg.Keep {
		removeFn = func() error {
			slog.Info("Keep initramfs archive", slog.String("path", path))
			return nil
		}
	} else {
		removeFn = func() error {
			slog.Debug("Remove initramfs archive", slog.String("path", path))
			return os.Remove(path)
		}
	}

	return path, removeFn, nil
}

// buildInitramfsArchive creates a new CPIO archive file according to the given
// [Initramfs] spec.
func buildInitramfsArchive(
	ctx context.Context,
	cfg Initramfs,
	initFileOpenFn virtfs.FileOpenFunc,
) (*virtfs.FS, error) {
	binaryFiles := []string{cfg.Binary}
	binaryFiles = append(binaryFiles, cfg.Files...)

	libs, err := sys.CollectLibsFor(ctx, binaryFiles...)
	if err != nil {
		return nil, fmt.Errorf("collect libs: %w", err)
	}

	initFn := func(b *fsBuilder, name string) error {
		return b.add(name, initFileOpenFn)
	}

	// In standalone mode, the main file is supposed to work as a complete
	// init matching our requirements.
	if cfg.StandaloneInit {
		initFn = func(b *fsBuilder, name string) error {
			return b.symlink("main", name)
		}
	}

	fsys, err := buildVirtFS(cfg, libs, initFn)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}

	return fsys, nil
}

// buildVirtFS creates a new [virtfs.FS].
//
// It does not read any source files. Only the FS file tree is created.
func buildVirtFS(
	cfg Initramfs,
	libs sys.LibCollection,
	initFn func(*fsBuilder, string) error,
) (*virtfs.FS, error) {
	fsys := virtfs.New()
	builder := fsBuilder{fsys}

	err := builder.addFilePathAs("main", cfg.Binary)
	if err != nil {
		return nil, err
	}

	err = initFn(&builder, "init")
	if err != nil {
		return nil, err
	}

	err = builder.addFilesTo(dataDir, cfg.Files, baseName)
	if err != nil {
		return nil, err
	}

	err = builder.addFilesTo(modulesDir, cfg.Modules, modName)
	if err != nil {
		return nil, err
	}

	err = builder.addFilesTo(libsDir, slices.Collect(libs.Libs()), baseName)
	if err != nil {
		return nil, err
	}

	err = builder.symlinkTo(libsDir, slices.Collect(libs.SearchPaths()))
	if err != nil && !errors.Is(err, virtfs.ErrFileExist) {
		return nil, err
	}

	return fsys, nil
}

// writeFSToTempFile writes the [fs.FS] as CPIO archive into a new temporary
// file and returns the absolute path to this file.
//
// If the given dir name is not empty, the file is created in this directory.
// Otherwise the default tempdir is used. See [os.CreateTemp].
func writeFSToTempFile(fsys fs.FS, dir string) (string, error) {
	file, err := os.CreateTemp(dir, "initramfs")
	if err != nil {
		return "", fmt.Errorf("create archive file: %w", err)
	}
	defer file.Close()

	writer := cpio.NewWriter(file)
	defer writer.Close()

	err = writer.AddFS(fsys)
	if err != nil {
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("write archive: %w", err)
	}

	return file.Name(), nil
}
