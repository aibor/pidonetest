// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package qemu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
)

// CommandSpec defines the parameters for a [Command].
type CommandSpec struct {
	// Path to the qemu-system binary
	Executable string

	// Path to the kernel to boot. The kernel should have Virtio-MMIO support
	// compiled in. If not, set the NoVirtioMMIO flag.
	Kernel string

	// Path to the initramfs to boot with. This is supposed to be a Initramfs
	// built with the initramfs sub package with an init that is built with
	// the sysinit sub package.
	Initramfs string

	// QEMU machine type to use. Depends on the QEMU binary used.
	Machine string

	// CPU type to use. Depends on machine type and QEMU binary used.
	CPU string

	// Number of CPUs for the guest.
	SMP uint64

	// Memory for the machine in MB.
	Memory uint64

	// Disable KVM support.
	NoKVM bool

	// Transport type for IO. This depends on machine type and the kernel.
	// TransportTypeIsa should always work, but will give only one slot for
	// microvm machine type. ARM type virt does not support ISA type at all.
	TransportType TransportType

	// ExtraArgs are  extra arguments that are passed to the QEMU command.
	// They must not interfere with the essential arguments set by the command
	// itself or an error will be returned on [Command.Run].
	ExtraArgs []Argument

	// Additional files attached to consoles besides the default one used for
	// stdout. They will be present in the guest system as "/dev/ttySx" or
	// "/dev/hvcx" where x is the index of the slice + 1.
	AdditionalConsoles []string

	// Arguments to pass to the init binary.
	InitArgs []string

	// Increase guest kernel logging.
	Verbose bool

	// ExitCodeFmt defines the format of the line communicating the exit code
	// from the guest. It must contain exactly one integer verb
	// (probably "%d").
	ExitCodeFmt string
}

// AddConsole adds an additional file to the QEMU command. This will be
// writable from the guest via the device name returned by this command.
// Console device number is starting at 1, as console 0 is the default stdout.
func (c *CommandSpec) AddConsole(file string) string {
	c.AdditionalConsoles = append(c.AdditionalConsoles, file)
	return c.TransportType.ConsoleDeviceName(uint(len(c.AdditionalConsoles)))
}

// Validate checks for known incompatibilities.
func (c *CommandSpec) Validate() error {
	if !c.TransportType.isKnown() {
		return &ArgumentError{
			"unknown transport type: " + c.TransportType.String(),
		}
	}

	switch c.Machine {
	case "microvm":
		switch {
		case c.TransportType == TransportTypePCI:
			return &ArgumentError{"microvm does not support pci transport"}
		case c.TransportType == TransportTypeISA &&
			len(c.AdditionalConsoles) > 0:
			return &ArgumentError{
				"microvm supports only one isa serial port, used for stdio",
			}
		}
	case "virt":
		if c.TransportType == TransportTypeISA {
			return &ArgumentError{"virt requires virtio-mmio"}
		}
	case "q35", "pc":
		if c.TransportType == TransportTypeMMIO {
			return &ArgumentError{
				c.Machine + " does not work with virtio-mmio",
			}
		}
	}

	return nil
}

// staticArguments compiles the argument list for the QEMU command.
func (c *CommandSpec) staticArguments() []Argument {
	args := []Argument{
		UniqueArg("kernel", c.Kernel),
		UniqueArg("initrd", c.Initramfs),
	}

	if c.Machine != "" {
		args = append(args, UniqueArg("machine", c.Machine))
	}

	if c.CPU != "" {
		args = append(args, UniqueArg("cpu", c.CPU))
	}

	if c.SMP != 0 {
		args = append(args, UniqueArg("smp", strconv.FormatUint(c.SMP, 10)))
	}

	if c.Memory != 0 {
		args = append(args, UniqueArg("m", strconv.FormatUint(c.Memory, 10)))
	}

	if !c.NoKVM {
		args = append(args, UniqueArg("enable-kvm", ""))
	}

	sharedDevices := map[TransportType]string{
		TransportTypePCI:  "virtio-serial-pci,max_ports=8",
		TransportTypeMMIO: "virtio-serial-device,max_ports=8",
	}
	if value, exists := sharedDevices[c.TransportType]; exists {
		args = append(args, RepeatableArg("device", value))
	}

	// Add stdout console.
	args = c.appendConsoleArgs(args, console{
		id:      "stdio",
		backend: "stdio",
	})

	args = append(args,
		// Disable video output.
		UniqueArg("display", "none"),
		// Disable QEMU monitor.
		UniqueArg("monitor", "none"),
		// Guest must not reboot.
		UniqueArg("no-reboot"),
		// Disable all default devices.
		UniqueArg("nodefaults"),
		// Do not load any user config files.
		UniqueArg("no-user-config"),
	)

	args = append(args, c.ExtraArgs...)

	kernelCmdline := strings.Join(c.kernelCmdlineArgs(), " ")
	args = append(args, RepeatableArg("append", kernelCmdline))

	return args
}

// kernelCmdlineArgs reruns the kernel cmdline arguments.
func (c *CommandSpec) kernelCmdlineArgs() []string {
	cmdline := []string{
		"console=" + c.TransportType.ConsoleDeviceName(0),
		"panic=-1",
		"mitigations=off",
		"initcall_blacklist=ahci_pci_driver_init",
	}

	// ACPI is necessary for SMP. With a single CPU, we can disable it to speed
	// up the boot considerably.
	if c.SMP == 1 {
		cmdline = append(cmdline, "acpi=off")
	}

	if !c.Verbose {
		cmdline = append(cmdline, "quiet")
	}

	if len(c.InitArgs) > 0 {
		cmdline = append(cmdline, "--")
		cmdline = append(cmdline, c.InitArgs...)
	}

	return cmdline
}

type console struct {
	id      string
	backend string
	opts    []string
}

func (c *CommandSpec) appendConsoleArgs(
	args []Argument,
	console console,
) []Argument {
	var devArg Argument

	switch c.TransportType {
	case TransportTypeISA:
		devArg = RepeatableArg("serial", "chardev:"+console.id)
	case TransportTypePCI, TransportTypeMMIO:
		devArg = RepeatableArg("device", "virtconsole,chardev="+console.id)
	default: // Ignore invalid transport types.
		return args
	}

	chardevOpts := []string{console.backend, "id=" + console.id}
	chardevOpts = append(chardevOpts, console.opts...)

	chardevArg := RepeatableArg("chardev", strings.Join(chardevOpts, ","))

	return append(args, chardevArg, devArg)
}

type Command struct {
	name         string
	args         []string
	stdoutParser stdoutParser

	consoleOutput map[string]string
}

// NewCommand builds the final [Command] with the given [CommandSpec].
//
// Optionally, a [HashStringFunc] function can be passed that overrides the
// default hash function. It is used for creating unique abstract unix socket
// names.
func NewCommand(spec CommandSpec, hashFn HashStringFunc) (*Command, error) {
	// Do some simple input validation to catch most obvious issues.
	err := spec.Validate()
	if err != nil {
		return nil, err
	}

	if hashFn == nil {
		hashFn = newHashStringFunc("virtrun-qemu-")
	}

	args := spec.staticArguments()
	consoles := map[string]string{}

	for idx, path := range spec.AdditionalConsoles {
		unixSockName := hashFn(path)
		args = spec.appendConsoleArgs(args, console{
			id:      "socket" + strconv.Itoa(idx),
			backend: "socket",
			opts: []string{
				// Linux provides support for abstract unix sockets (see
				// unix(7)). They are independent of the file system and exist
				// only in the abstract socket name space. It must have a
				// unique name, though. It is automatically removed when the
				// listening socket is closed. Here, we configure QEMU to be
				// the client and connect to an abstract socket that must exist
				// already.
				"path=" + unixSockName,
				"abstract=on",
			},
		})
		consoles[unixSockName] = path
	}

	cmdArgs, err := BuildArgumentStrings(args)
	if err != nil {
		return nil, err
	}

	if spec.ExitCodeFmt == "" {
		return nil, &ArgumentError{"ExitCodeFmt must not be empty"}
	}

	cmd := &Command{
		name:          spec.Executable,
		args:          cmdArgs,
		consoleOutput: consoles,
		stdoutParser: stdoutParser{
			ExitCodeFmt: spec.ExitCodeFmt,
			Verbose:     spec.Verbose,
		},
	}

	return cmd, nil
}

// String prints the human readable string representation of the command.
func (c *Command) String() string {
	elems := append([]string{c.name}, c.args...)
	return strings.Join(elems, " ")
}

// unixConsoleProcessor creates a function that accepts only one connection on
// the given listener. For this connection a consoleProcessor is started that
// writes the output into the file at the given path.
func unixConsoleProcessor(listener net.Listener, path string) func() error {
	// Accepts one connection. Expected to be connected from the QEMU process.
	// Opens the output file on demand.
	return func() error {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("socket: %w", err)
		}
		defer conn.Close()

		dst, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("output: %w", err)
		}
		defer dst.Close()

		processor := consoleProcessor{
			dst: dst,
			src: conn,
		}

		return processor.run()
	}
}

// Run the [Command] with the given [context.Context].
//
// Output processors are setup and the command is executed. Returns without
// error only if the guest system correctly communicated exit code 0. In any
// other case, an error is returned. If the QEMU command itself failed,
// a [CommandError] with the guest flag unset is returned. If the guest
// returned an error or failed a [CommandError] with guest flag set is
// returned.
func (c *Command) Run(
	ctx context.Context,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	processors, ctx := errgroup.WithContext(ctx)

	cmd := exec.CommandContext(ctx, c.name, c.args...)

	// The default cancel function set by [exec.CommandContext] sends SIGKILL
	// to the process. This makes it impossible for QEMU to shutdown gracefully
	// which messes up terminal stdio and leaves the terminal in a broken state.
	cmd.Cancel = func() error {
		return cmd.Process.Signal(os.Interrupt)
	}

	cmd.Stdin = stdin
	cmd.Stderr = stderr

	// Setup stdout processor that parses the output for the sysinit's exit
	// code line.
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	processor := consoleProcessor{
		dst: stdout,
		src: outPipe,
		fn:  c.stdoutParser.Parse,
	}

	processors.Go(processor.run)

	runErr := run(cmd, processors, c.consoleOutput)

	// Let output processors terminate gracefully.
	if err := processors.Wait(); err != nil {
		return fmt.Errorf("processors: %w", err)
	}

	if runErr != nil {
		return runErr
	}

	return c.stdoutParser.GuestSuccessful()
}

// run runs the given [exec.Cmd] after setting up the output processors and
// stating them in the given processors [errgroup.Group]. It terminates the
// input listeners on exit, so the caller can wait for the graceful shutdown of
// the output processors.
func run(
	cmd *exec.Cmd,
	processors *errgroup.Group,
	outputs map[string]string,
) error {
	listeners := []io.Closer{}

	defer func() {
		for _, closer := range slices.Backward(listeners) {
			if err := closer.Close(); err != nil {
				slog.Error(
					"Failed to close qemu output listener",
					slog.Any("error", err),
				)
			}
		}
	}()

	for sockName, path := range outputs {
		// A unix socket name starting with a null byte is interpreted as an
		// abstract unix socket address (see unix(7)).
		listener, err := net.Listen("unix", "\x00"+sockName)
		if err != nil {
			return fmt.Errorf("listen: %w", err)
		}

		listeners = append(listeners, listener)
		processors.Go(unixConsoleProcessor(listener, path))
	}

	if err := cmd.Run(); err != nil {
		return wrapExitError(err)
	}

	return nil
}

func wrapExitError(err error) error {
	var exitErr *exec.ExitError

	if !errors.As(err, &exitErr) {
		return fmt.Errorf("qemu command: %w", err)
	}

	return &CommandError{
		Err:      err,
		ExitCode: exitErr.ExitCode(),
	}
}
