package buildcheck

import (
	"fmt"
	"runtime/debug"
	"strings"
)

func Optimized(info *debug.BuildInfo) error {
	if info == nil {
		return fmt.Errorf("missing Go build information")
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "-race", "-msan", "-asan":
			if setting.Value == "true" {
				return fmt.Errorf("instrumented prover build")
			}
		case "-gcflags":
			for _, flag := range strings.Fields(strings.ReplaceAll(setting.Value, "=", " ")) {
				if flag == "-N" || flag == "-l" {
					return fmt.Errorf("disabled Go compiler optimization")
				}
			}
		case "-tags":
			for _, tag := range strings.FieldsFunc(setting.Value, func(r rune) bool { return r == ',' || r == ' ' }) {
				if tag == "purego" || tag == "noasm" {
					return fmt.Errorf("disabled cryptographic assembly")
				}
			}
		}
	}
	return nil
}

func Current() error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("missing Go build information")
	}
	return Optimized(info)
}
