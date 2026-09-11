//go:build !bench_profile

package main

// Empty functions inline away in the ordinary prover build.
type profileStamp struct{}

func profileReset()                                      {}
func profileStart() profileStamp                         { return profileStamp{} }
func profileEnd(_ string, _ profileStamp)                {}
func profileResult(result map[string]any) map[string]any { return result }
