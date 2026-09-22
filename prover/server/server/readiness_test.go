package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessGate(t *testing.T) {
	readiness := &Readiness{}
	request := httptest.NewRequest(http.MethodGet, "/ready", nil)
	response := httptest.NewRecorder()
	readiness.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal(response.Code)
	}
	handler := proveHandler{readiness: readiness}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/prove", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal(response.Code)
	}
	readiness.MarkReady()
	response = httptest.NewRecorder()
	readiness.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
}

func TestReadinessIsPublic(t *testing.T) {
	readiness := &Readiness{}
	readiness.MarkReady()
	handler := conditionalAuthMiddleware("test-key")(readiness)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	if !requiresAuthentication("/prove") {
		t.Fatal("proof endpoint lost authentication")
	}
}
