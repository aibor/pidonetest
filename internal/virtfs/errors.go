// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package virtfs

import (
	"errors"
	"io/fs"
)

var (
	// ErrFileNotExist is returned if a tree node that is looked up does not
	// exist.
	ErrFileNotExist = fs.ErrNotExist

	// ErrFileExist is returned if a tree node exists that was not expected.
	ErrFileExist = fs.ErrExist

	// ErrFileInvalid is returned if a file is invalid for the requested
	// operation.
	ErrFileInvalid = fs.ErrInvalid

	// ErrFileNotDir is returned if a file exists but is not a directory.
	ErrFileNotDir = errors.New("not a directory")

	// ErrFileNotRegular is returned if the source is not a regular file.
	ErrFileNotRegular = errors.New("source is not a regular file")

	// ErrInvalidArgument is returned if an invalid argument is given.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrSymlinkTooDeep is returned if there are too many symbolic links to
	// follow.
	ErrSymlinkTooDeep = errors.New("nested links too deep")
)

// PathError records an error and the operation and file path that caused it.
type PathError = fs.PathError
