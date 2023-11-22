package initramfs

import (
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aibor/virtrun/internal/archive"
	"github.com/aibor/virtrun/internal/files"
)

func TestInitramfsNew(t *testing.T) {
	testFS := fstest.MapFS{
		"input": &fstest.MapFile{},
	}
	testFile, err := testFS.Open("input")
	require.NoError(t, err)

	verifyInitEntry := func(expected files.Entry) func(*testing.T, *Initramfs) {
		return func(t *testing.T, i *Initramfs) {
			entry, err := i.fileTree.GetEntry("/init")
			require.NoError(t, err, "must get init entry")
			assert.Equal(t, expected, *entry)
		}
	}

	tests := []struct {
		name     string
		initFile InitFile
		verify   func(*testing.T, *Initramfs)
	}{
		{
			name:     "init from real path",
			initFile: InitFilePath("first"),
			verify: verifyInitEntry(files.Entry{
				Type:        files.TypeRegular,
				RelatedPath: "first",
			}),
		},
		{
			name:     "init from embedded file",
			initFile: InitFileVirtual(testFile),
			verify: verifyInitEntry(files.Entry{
				Type:   files.TypeVirtual,
				Source: testFile,
			}),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			i := New(tt.initFile)
			tt.verify(t, i)
		})
	}
}

func TestInitramfsAddFile(t *testing.T) {
	archive := New(InitFilePath("first"))

	require.NoError(t, archive.AddFile("dir", "second", "rel/third"))
	require.NoError(t, archive.AddFile("dir", "", "/abs/fourth"))

	expected := map[string]string{
		"second": "rel/third",
		"fourth": "/abs/fourth",
	}

	for file, relPath := range expected {
		path := filepath.Join("dir", file)
		e, err := archive.fileTree.GetEntry(path)
		require.NoError(t, err, path)
		assert.Equal(t, files.TypeRegular, e.Type)
		assert.Equal(t, relPath, e.RelatedPath)
	}
}

func TestInitramfsAddFiles(t *testing.T) {
	archive := New(InitFilePath("first"))

	require.NoError(t, archive.AddFiles("dir", "second", "rel/third", "/abs/fourth"))
	require.NoError(t, archive.AddFiles("dir", "fifth"))
	require.NoError(t, archive.AddFiles("dir"))

	expected := map[string]string{
		"second": "second",
		"third":  "rel/third",
		"fourth": "/abs/fourth",
		"fifth":  "fifth",
	}

	for file, relPath := range expected {
		path := filepath.Join("dir", file)
		e, err := archive.fileTree.GetEntry(path)
		require.NoError(t, err, path)
		assert.Equal(t, files.TypeRegular, e.Type)
		assert.Equal(t, relPath, e.RelatedPath)
	}
}

func TestInitramfsWriteTo(t *testing.T) {
	testFS := fstest.MapFS{
		"input": &fstest.MapFile{},
	}
	testFile, err := testFS.Open("input")
	require.NoError(t, err)

	test := func(entry *files.Entry, w *archive.MockWriter) error {
		i := Initramfs{}
		_, err := i.fileTree.GetRoot().AddEntry("init", entry)
		require.NoError(t, err)
		return i.writeTo(w, testFS)
	}

	t.Run("unknown file type", func(t *testing.T) {
		err := test(&files.Entry{Type: files.Type(99)}, &archive.MockWriter{})
		assert.ErrorContains(t, err, "unknown file type 99")
	})

	t.Run("nonexisting source", func(t *testing.T) {
		entry := &files.Entry{
			Type:        files.TypeRegular,
			RelatedPath: "nonexisting",
		}
		err := test(entry, &archive.MockWriter{})
		assert.ErrorContains(t, err, "open nonexisting: file does not exist")
	})

	t.Run("existing files", func(t *testing.T) {
		tests := []struct {
			name  string
			entry files.Entry
			mock  archive.MockWriter
		}{
			{
				name: "regular",
				entry: files.Entry{
					Type:        files.TypeRegular,
					RelatedPath: "/input",
				},
				mock: archive.MockWriter{
					Path:   "/init",
					Source: testFile,
					Mode:   0755,
				},
			},
			{
				name: "directory",
				entry: files.Entry{
					Type: files.TypeDirectory,
				},
				mock: archive.MockWriter{
					Path: "/init",
				},
			},
			{
				name: "link",
				entry: files.Entry{
					Type:        files.TypeLink,
					RelatedPath: "/lib",
				},
				mock: archive.MockWriter{
					Path:        "/init",
					RelatedPath: "/lib",
				},
			},
			{
				name: "virtual",
				entry: files.Entry{
					Type:   files.TypeVirtual,
					Source: testFile,
				},
				mock: archive.MockWriter{
					Path:   "/init",
					Source: testFile,
					Mode:   0755,
				},
			},
		}

		for _, tt := range tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Run("works", func(t *testing.T) {
					i := Initramfs{}
					_, err := i.fileTree.GetRoot().AddEntry("init", &tt.entry)
					require.NoError(t, err)
					mock := archive.MockWriter{}
					err = i.writeTo(&mock, testFS)
					require.NoError(t, err)
					assert.Equal(t, tt.mock, mock)
				})
				t.Run("fails", func(t *testing.T) {
					i := Initramfs{}
					_, err := i.fileTree.GetRoot().AddEntry("init", &tt.entry)
					require.NoError(t, err)
					mock := archive.MockWriter{Err: assert.AnError}
					err = i.writeTo(&mock, testFS)
					assert.Error(t, err, assert.AnError)
				})
			})
		}
	})
}

func TestInitramfsResolveLinkedLibs(t *testing.T) {
	t.Setenv("LD_LIBRARY_PATH", "../internal/files/testdata/lib")
	irfs := New(InitFilePath("../internal/files/testdata/bin/main"))
	err := irfs.AddRequiredSharedObjects("")
	require.NoError(t, err)

	expectedFiles := map[string]files.Entry{
		"/lib": {
			Type: files.TypeDirectory,
		},
		"/lib/libfunc2.so": {
			Type:        files.TypeRegular,
			RelatedPath: "../internal/files/testdata/lib/libfunc2.so",
		},
		"/lib/libfunc3.so": {
			Type:        files.TypeRegular,
			RelatedPath: "../internal/files/testdata/lib/libfunc3.so",
		},
		"/lib/libfunc1.so": {
			Type:        files.TypeRegular,
			RelatedPath: "../internal/files/testdata/lib/libfunc1.so",
		},
	}

	for f, e := range expectedFiles {
		entry, err := irfs.fileTree.GetEntry(f)
		if assert.NoError(t, err, f) {
			assert.Equal(t, e.Type, entry.Type, f)
			if e.RelatedPath != "" {
				expectedPath, err := filepath.Abs(e.RelatedPath)
				require.NoError(t, err)
				assert.Equal(t, expectedPath, entry.RelatedPath, f)
			}
		}
	}
}
