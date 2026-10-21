// Package refusal names the constraint refusing a witness in gnark's test engine.
package refusal

import (
	"strings"
	"testing"
)

// Require requires err to be a failed assertion whose trace names every frame, the
// engine reports the first assertion the witness breaks with its call stack.
func Require(t testing.TB, err error, frames ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("solved")
	}
	for _, frame := range frames {
		if !strings.Contains(err.Error(), frame) {
			t.Fatalf("refused outside %s: %v", frame, err)
		}
	}
}
