// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package virtfs_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/aibor/virtrun/internal/virtfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFiles_TestFS(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		fsys := virtfs.New()

		err := fstest.TestFS(fsys)
		require.NoError(t, err)
	})

	t.Run("non-empty", func(t *testing.T) {
		sourceFS := fstest.MapFS{
			"file": &fstest.MapFile{},
		}

		fsys := virtfs.New()

		err := fsys.Mkdir("dir")
		require.NoError(t, err)

		err = fsys.MkdirAll("dir/a/b/c")
		require.NoError(t, err)

		err = fsys.Add("dir/file", func() (fs.File, error) {
			return sourceFS.Open("file")
		})
		require.NoError(t, err)

		err = fsys.Symlink("dir/file", "dir/link")
		require.NoError(t, err)

		err = fstest.TestFS(fsys, "dir", "dir/a/b/c", "dir/file", "dir/link")
		require.NoError(t, err)
	})
}

func TestFS_Add(t *testing.T) {
	testFS := fstest.MapFS{
		"test": &fstest.MapFile{
			Data: []byte("content"),
		},
	}

	tests := []struct {
		name        string
		path        string
		prepare     func(fsys *virtfs.FS) error
		expectedErr error
	}{
		{
			name: "new",
			path: "test",
		},
		{
			name: "new in dir",
			path: "dir/test",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("dir")
			},
		},
		{
			name: "parent valid symlink",
			path: "dir/test",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("/", "dir")
			},
		},
		{
			name: "exists as file",
			path: "test",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Add("test", func() (fs.File, error) {
					return testFS.Open("test")
				})
			},
			expectedErr: virtfs.ErrFileExist,
		},
		{
			name: "exists as other",
			path: "test",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("test")
			},
			expectedErr: virtfs.ErrFileExist,
		},
		{
			name: "parent not a dir",
			path: "dir/test",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Add("dir", func() (fs.File, error) {
					return nil, assert.AnError
				})
			},
			expectedErr: virtfs.ErrFileNotDir,
		},
		{
			name:        "missing parent",
			path:        "dir/test",
			expectedErr: virtfs.ErrFileNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := virtfs.New()

			if tt.prepare != nil {
				err := tt.prepare(fsys)
				require.NoError(t, err)
			}

			err := fsys.Add(tt.path, func() (fs.File, error) {
				return testFS.Open("test")
			})
			require.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestFS_Mkdir(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		prepare     func(fsys *virtfs.FS) error
		expectedErr error
	}{
		{
			name: "new",
			path: "dir",
		},
		{
			name: "new in dir",
			path: "dir/sub",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("dir")
			},
		},
		{
			name: "parent valid symlink",
			path: "dir/sub",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("/", "dir")
			},
		},
		{
			name: "exists as dir",
			path: "dir",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("dir")
			},
			expectedErr: virtfs.ErrFileExist,
		},
		{
			name: "exists as other",
			path: "dir",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("somewhere", "dir")
			},
			expectedErr: virtfs.ErrFileExist,
		},
		{
			name: "parent not a dir",
			path: "dir/sub",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Add("dir", func() (fs.File, error) {
					return nil, assert.AnError
				})
			},
			expectedErr: virtfs.ErrFileNotDir,
		},
		{
			name:        "missing parent",
			path:        "dir/sub",
			expectedErr: virtfs.ErrFileNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := virtfs.New()

			if tt.prepare != nil {
				err := tt.prepare(fsys)
				require.NoError(t, err)
			}

			err := fsys.Mkdir(tt.path)
			require.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestFS_MkdirAll(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		prepare     func(fsys *virtfs.FS) error
		expectedErr error
	}{
		{
			name: "new",
			path: "dir",
		},
		{
			name: "new in dir",
			path: "dir/sub",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("dir")
			},
		},
		{
			name: "exists as dir",
			path: "dir",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("dir")
			},
		},
		{
			name: "exists as other",
			path: "dir",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Add("dir", func() (fs.File, error) {
					return nil, assert.AnError
				})
			},
			expectedErr: virtfs.ErrFileNotDir,
		},
		{
			name: "parent not a dir",
			path: "dir/sub/subsub",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Add("dir", func() (fs.File, error) {
					return nil, assert.AnError
				})
			},
			expectedErr: virtfs.ErrFileNotDir,
		},
		{
			name: "missing parent",
			path: "dir/sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := virtfs.New()

			if tt.prepare != nil {
				err := tt.prepare(fsys)
				require.NoError(t, err)
			}

			err := fsys.MkdirAll(tt.path)
			require.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestFS_Symlink(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		prepare     func(fsys *virtfs.FS) error
		expectedErr error
	}{
		{
			name: "new",
			path: "link",
		},
		{
			name: "new in dir",
			path: "dir/link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("dir")
			},
		},
		{
			name: "parent valid symlink",
			path: "dir/link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("/", "dir")
			},
		},
		{
			name: "parent self symlink",
			path: "dir/sub",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("dir", "dir")
			},
			expectedErr: virtfs.ErrSymlinkTooDeep,
		},
		{
			name: "exists as link",
			path: "link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("somewhere", "link")
			},
			expectedErr: virtfs.ErrFileExist,
		},
		{
			name: "exists as other",
			path: "link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("link")
			},
			expectedErr: virtfs.ErrFileExist,
		},
		{
			name: "parent not a dir",
			path: "dir/link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Add("dir", func() (fs.File, error) {
					return nil, assert.AnError
				})
			},
			expectedErr: virtfs.ErrFileNotDir,
		},
		{
			name:        "missing parent",
			path:        "dir/link",
			expectedErr: virtfs.ErrFileNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := virtfs.New()

			if tt.prepare != nil {
				err := tt.prepare(fsys)
				require.NoError(t, err)
			}

			err := fsys.Symlink("somewhere", tt.path)
			require.ErrorIs(t, err, tt.expectedErr)
		})
	}
}

func TestFS_ReadLink(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		prepare     func(fsys *virtfs.FS) error
		expected    string
		expectedErr error
	}{
		{
			name: "exists as link",
			path: "link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("somewhere", "link")
			},
			expected: "somewhere",
		},
		{
			name: "exists as other",
			path: "link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Mkdir("link")
			},
			expectedErr: virtfs.ErrFileInvalid,
		},
		{
			name: "parent not a dir",
			path: "dir/link",
			prepare: func(fsys *virtfs.FS) error {
				return fsys.Symlink("somewhere", "dir")
			},
			expectedErr: virtfs.ErrFileNotExist,
		},
		{
			name:        "missing parent",
			path:        "dir/link",
			expectedErr: virtfs.ErrFileNotExist,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := virtfs.New()

			if tt.prepare != nil {
				err := tt.prepare(fsys)
				require.NoError(t, err)
			}

			actual, err := fsys.ReadLink(tt.path)
			require.ErrorIs(t, err, tt.expectedErr)

			assert.Equal(t, tt.expected, actual)
		})
	}
}
