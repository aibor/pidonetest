//go:build integration

package integrationtesting

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuestSysinit(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	goBinDir := filepath.Join(cwd, "gobin")

	cmd := exec.Command("go", "install", "-buildvcs=false", "../cmd/virtrun")
	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("GOBIN=%s", goBinDir),
		"GOARCH=",
	)

	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Log(string(out))
	}
	require.NoError(t, err)

	absKernelDir, err := filepath.Abs(KernelCacheDir)
	require.NoError(t, err)

	test := func(standalone bool) func(t *testing.T) {
		return func(t *testing.T) {
			for _, kernel := range TestKernels {
				kernel := kernel
				t.Run(kernel.String(), func(t *testing.T) {
					execArgs := []string{
						filepath.Join(goBinDir, "virtrun"),
						"-kernel", kernel.Path(absKernelDir),
						"-verbose",
					}
					testTags := []string{
						"integration_guest",
					}

					if standalone {
						execArgs = append(execArgs, "-standalone")
						testTags = append(testTags, "standalone")
					}
					args := []string{
						"test",
						"-v",
						"-timeout", "2m",
						"-exec", strings.Join(execArgs, " "),
						"-tags", strings.Join(testTags, ","),
						"-cover",
						"-coverprofile", "/tmp/cover.out",
						"-coverpkg", "github.com/aibor/virtrun/sysinit",
						"./guest/...",
					}

					cmd = exec.Command("go", args...)
					cmd.Env = append(
						os.Environ(),
						fmt.Sprintf("GOARCH=%s", kernel.Arch),
					)
					out, err = cmd.CombinedOutput()
					if len(out) > 0 {
						t.Log(string(out))
					}
					assert.NoError(t, err)
				})
			}
		}
	}

	t.Run("wrapped", test(false))
	t.Run("standalone", test(true))
}
