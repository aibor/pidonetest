// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package initramfs

import "io/fs"

// ReadLinkFS is a [fs.FS] with an additional method for reading the target of
// a symbolic link.
//
// Replace with [fs.ReadLinkFS] once available (planned for 1.25). See
// https://github.com/golang/go/issues/49580
type ReadLinkFS interface {
	fs.FS

	ReadLink(name string) (string, error)
	Lstat(name string) (fs.FileInfo, error)
}
