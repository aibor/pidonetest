package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aibor/virtrun"
	"github.com/aibor/virtrun/qemu"
)

type config struct {
	cmd                 *virtrun.Command
	arch                string
	binaries            []string
	standalone          bool
	noGoTestFlagRewrite bool
	keepInitramfs       bool
}

func (cfg *config) parseArgs(args []string) error {
	fsName := fmt.Sprintf("%s [flags...] binaries... [initflags...]", args[0])
	fs := flag.NewFlagSet(fsName, flag.ContinueOnError)

	fs.StringVar(
		&cfg.cmd.Executable,
		"qemu-bin",
		cfg.cmd.Executable,
		"QEMU binary to use",
	)

	fs.StringVar(
		&cfg.cmd.Kernel,
		"kernel",
		cfg.cmd.Kernel,
		"path to kernel to use",
	)

	fs.StringVar(
		&cfg.cmd.Machine,
		"machine",
		cfg.cmd.Machine,
		"QEMU machine type to use",
	)

	fs.StringVar(
		&cfg.cmd.CPU,
		"cpu",
		cfg.cmd.CPU,
		"QEMU CPU type to use",
	)

	fs.BoolVar(
		&cfg.cmd.NoKVM,
		"nokvm",
		cfg.cmd.NoKVM,
		"disable hardware support",
	)

	fs.Func(
		"transport",
		fmt.Sprintf("io transport type: 0=isa, 1=pci, 2=mmio (default %d)", cfg.cmd.TransportType),
		func(s string) error {
			t, err := strconv.ParseUint(s, 10, 2)
			if err != nil {
				return err
			}
			if t > 2 {
				return fmt.Errorf("unknown transport type")
			}
			cfg.cmd.TransportType = qemu.TransportType(t)
			return nil
		},
	)

	fs.BoolVar(
		&cfg.cmd.Verbose,
		"verbose",
		cfg.cmd.Verbose,
		"enable verbose guest system output",
	)

	fs.Func(
		"memory",
		fmt.Sprintf("memory (in MB) for the QEMU VM (default %dMB)", cfg.cmd.Memory),
		func(s string) error {
			mem, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return err
			}
			if mem < 128 {
				return fmt.Errorf("less than 128 MB is not sufficient")
			}
			cfg.cmd.Memory = uint(mem)
			return nil
		},
	)

	fs.Func(
		"smp",
		fmt.Sprintf("number of CPUs for the QEMU VM (default %d)", cfg.cmd.SMP),
		func(s string) error {
			mem, err := strconv.ParseUint(s, 10, 4)
			if err != nil {
				return err
			}
			if mem < 1 {
				return fmt.Errorf("must not be less than 1")
			}

			cfg.cmd.SMP = uint(mem)

			return nil
		},
	)

	fs.BoolVar(
		&cfg.standalone,
		"standalone",
		cfg.standalone,
		"run first given binary as init itself. Use this if it has virtrun support built in.",
	)

	fs.BoolVar(
		&cfg.noGoTestFlagRewrite,
		"noGoTestFlagRewrite",
		cfg.noGoTestFlagRewrite,
		"disable automatic go test flag rewrite for file based output.",
	)

	fs.BoolVar(
		&cfg.keepInitramfs,
		"keepInitramfs",
		cfg.keepInitramfs,
		"do not delete initramfs once qemu is done. Intended for debugging. "+
			"The path to the file is printed on stderr",
	)

	// Parses arguments up to the first one that is not prefixed with a "-" or
	// is "--".
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	// Fail like flag does.
	failf := func(format string, a ...any) error {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(fs.Output(), msg)
		fs.Usage()
		return fmt.Errorf(msg)
	}

	if cfg.cmd.Kernel == "" {
		return failf("no kernel given (use env var QEMU_KERNEL or flag -kernel)")
	}

	// Consider all positional arguments until one begins with "-" as binary
	// files that should be added to the initramfs. All further arguments
	// are added as [qemu.Command.InitArgs] that will be passed to the guest
	// system's init program.
	var binariesDone bool
	for _, arg := range fs.Args() {
		switch {
		case strings.HasPrefix(arg, "-"):
			binariesDone = true
			fallthrough
		case binariesDone:
			cfg.cmd.InitArgs = append(cfg.cmd.InitArgs, arg)
		default:
			path, err := filepath.Abs(arg)
			if err != nil {
				return failf("absolute path for %s: %v", arg, err)
			}
			cfg.binaries = append(cfg.binaries, path)
		}
	}

	if len(cfg.binaries) < 1 {
		return failf("no binary given")
	}

	return nil
}
