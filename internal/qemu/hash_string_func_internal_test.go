// SPDX-FileCopyrightText: 2024 Tobias Böhm <code@aibor.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

package qemu

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashStringFunc(t *testing.T) {
	t.Run("same func", func(t *testing.T) {
		fn := newHashStringFunc("test-")

		t.Run("same input", func(t *testing.T) {
			a, b := fn("4"), fn("4")
			assert.Equal(t, a, b)
		})

		t.Run("different input", func(t *testing.T) {
			a, b := fn("4"), fn("5")
			assert.NotEqual(t, a, b)
		})
	})

	t.Run("different func", func(t *testing.T) {
		fn1 := newHashStringFunc("test-")
		fn2 := newHashStringFunc("test-")

		t.Run("same input", func(t *testing.T) {
			a, b := fn1("4"), fn2("4")
			assert.NotEqual(t, a, b)
		})
	})
}
