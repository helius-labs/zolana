//go:build bench_profile

package main

import (
	"encoding/json"
	"time"
)

// Diagnostics only. Browser calls are serialized in their worker.
type profileStamp = time.Time

var profileTimings map[string]float64

func profileReset()              { profileTimings = make(map[string]float64) }
func profileStart() profileStamp { return time.Now() }
func profileEnd(name string, start profileStamp) {
	if profileTimings != nil {
		profileTimings[name] += float64(time.Since(start)) / float64(time.Millisecond)
	}
}
func profileResult(result map[string]any) map[string]any {
	data, err := json.Marshal(profileTimings)
	if err == nil {
		result["profile"] = string(data)
	}
	return result
}
