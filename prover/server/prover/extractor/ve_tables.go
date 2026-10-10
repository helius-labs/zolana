package extractor

import (
	"os"
	"path/filepath"
	"strings"
)

// ExtractVETables writes the generated data and certificate modules of the
// VerifiableEncryption library under the Lake root leanRoot: AesTables.lean,
// CombTables.lean, EmcurveChecks.lean, Field/Certificate.lean and the
// Field/Instances*.lean modules (stale instance modules are removed first).
// The instance modules are derived from the in-memory circuit extraction, so
// they agree with extract-ve-circuit. It returns the bytes written.
func ExtractVETables(leanRoot string) (int, error) {
	lib := filepath.Join(leanRoot, "VerifiableEncryption")
	checks, err := CollectEmcurveChecks()
	if err != nil {
		return 0, err
	}
	modules, err := extractVE()
	if err != nil {
		return 0, err
	}
	instances, err := RenderEmcurveInstances(checks, modules)
	if err != nil {
		return 0, err
	}
	files := map[string]string{
		filepath.Join(lib, "AesTables.lean"):            ExtractAesTables(),
		filepath.Join(lib, "CombTables.lean"):           ExtractCombTables(),
		filepath.Join(lib, "EmcurveChecks.lean"):        RenderEmcurveChecks(checks),
		filepath.Join(lib, "Field", "Certificate.lean"): RenderEmcurveCertificate(checks),
	}
	for module, source := range instances {
		files[filepath.Join(lib, "Field", strings.TrimPrefix(module, "VerifiableEncryption.Field.")+".lean")] = source
	}
	stale, err := filepath.Glob(filepath.Join(lib, "Field", "Instances*.lean"))
	if err != nil {
		return 0, err
	}
	for _, path := range stale {
		if err := os.Remove(path); err != nil {
			return 0, err
		}
	}
	written := 0
	for path, source := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return 0, err
		}
		if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
			return 0, err
		}
		written += len(source)
	}
	return written, nil
}
