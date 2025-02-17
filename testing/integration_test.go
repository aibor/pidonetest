// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build integration

//go:generate env CGO_ENABLED=0 go build -v -trimpath -buildvcs=false -o bin/ ./cmd/...

//go:generate -command guesttest env CGO_ENABLED=0 go test -c -cover -covermode atomic -coverpkg github.com/aibor/virtrun/sysinit ./guest/
//go:generate guesttest -c -tags integration_guest -o bin/guest.test
//go:generate guesttest -c -tags integration_guest,standalone -o bin/guest.standalone.test

package integration_test

import (
	"bytes"
	"context"
	"flag"
	"testing"
	"time"

	"github.com/aibor/virtrun/internal/cmd"
	"github.com/aibor/virtrun/internal/qemu"
	"github.com/aibor/virtrun/internal/virtrun"
	"github.com/stretchr/testify/require"
)

//nolint:gochecknoglobals
var (
	KernelPath            = "/kernels/vmlinuz"
	ForceTransportTypePCI bool
	Verbose               bool
)

//nolint:gochecknoinits
func init() {
	flag.Var(
		(*cmd.FilePath)(&KernelPath),
		"kernel.path",
		"absolute path of the test kernel",
	)
	flag.BoolVar(
		&ForceTransportTypePCI,
		"force-pci",
		ForceTransportTypePCI,
		"force transport type virtio-pci instead of arch default",
	)
	flag.BoolVar(
		&Verbose,
		"verbose",
		Verbose,
		"show complete guest output",
	)
}

func TestIntegration(t *testing.T) {
	t.Parallel()

	verboseFlag := func() string {
		if Verbose {
			return "-test.v"
		}

		return ""
	}

	tests := []struct {
		name       string
		bin        string
		args       []string
		standalone bool
		nativeOnly bool
		requireErr require.ErrorAssertionFunc
	}{
		{
			name:       "return 0",
			bin:        "bin/return",
			args:       []string{"0"},
			requireErr: require.NoError,
		},
		{
			name: "return 55",
			bin:  "bin/return",
			args: []string{"55"},
			requireErr: func(t require.TestingT, err error, _ ...any) {
				var qemuErr *qemu.CommandError

				require.ErrorAs(t, err, &qemuErr)
				require.Equal(t, 55, qemuErr.ExitCode)
			},
		},
		{
			name:       "panic",
			bin:        "bin/panic",
			standalone: true,
			requireErr: func(t require.TestingT, err error, _ ...any) {
				require.ErrorIs(t, err, qemu.ErrGuestPanic)
			},
		},
		{
			name: "oom",
			bin:  "bin/oom",
			args: []string{"128"},
			requireErr: func(t require.TestingT, err error, _ ...any) {
				require.ErrorIs(t, err, qemu.ErrGuestOom)
			},
		},
		{
			name:       "linked",
			bin:        "../internal/sys/testdata/bin/main",
			nativeOnly: true,
			requireErr: func(t require.TestingT, err error, _ ...any) {
				var qemuErr *qemu.CommandError
				require.ErrorAs(t, err, &qemuErr)
				require.Equal(t, 73, qemuErr.ExitCode)
			},
		},
		{
			name: "guest test",
			bin:  "bin/guest.test",
			args: []string{
				verboseFlag(),
				"-cpus", "2",
			},
			requireErr: require.NoError,
		},
		{
			name:       "guest standalone test",
			bin:        "bin/guest.standalone.test",
			standalone: true,
			args: []string{
				verboseFlag(),
				"-test.gocoverdir=/tmp/",
				"-test.coverprofile=/tmp/cover.out",
				"-cpus", "2",
			},
			requireErr: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			binary, err := cmd.AbsoluteFilePath(tt.bin)
			require.NoError(t, err)

			spec := &virtrun.Spec{
				Qemu: virtrun.Qemu{
					Kernel:   KernelPath,
					Verbose:  Verbose,
					CPU:      "max",
					Memory:   128,
					SMP:      2,
					InitArgs: tt.args,
				},
				Initramfs: virtrun.Initramfs{
					Binary:         binary,
					StandaloneInit: tt.standalone,
				},
			}

			if ForceTransportTypePCI {
				spec.Qemu.TransportType = qemu.TransportTypePCI
			}

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			t.Cleanup(cancel)

			var stdOut, stdErr bytes.Buffer

			err = virtrun.Run(ctx, spec, nil, &stdOut, &stdErr)

			t.Log(stdOut.String())
			t.Log(stdErr.String())

			tt.requireErr(t, err)
		})
	}
}
