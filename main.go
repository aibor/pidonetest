// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"

	"github.com/aibor/virtrun/internal/cmd"
)

func main() {
	os.Exit(cmd.Run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
