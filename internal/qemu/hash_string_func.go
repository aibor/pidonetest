// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package qemu

import (
	"hash/maphash"
	"strconv"
)

// HashStringFunc returns a hash for the given input string.
type HashStringFunc func(s string) string

// newHashStringFunc us es [maphash.String] for creating hash strings prefixed
// with the given prefix. Intended to be used for abstract unix socket names.
func newHashStringFunc(prefix string) HashStringFunc {
	seed := maphash.MakeSeed()

	return func(s string) string {
		hash := strconv.FormatUint(maphash.String(seed, s), 32)
		return prefix + hash
	}
}
