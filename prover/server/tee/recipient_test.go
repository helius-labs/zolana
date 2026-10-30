package tee

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRecipientIDVectors(t *testing.T) {
	raw, err := os.ReadFile(testdata + "/recipient_ids.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Header  string `json:"header"`
		Vectors []struct {
			Key string `json:"hpke_public_key"`
			ID  string `json:"recipient_id"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Header != HeaderKeyID {
		t.Fatal("recipient header")
	}
	for _, vector := range fixture.Vectors {
		key, err := hex.DecodeString(vector.Key)
		if err != nil {
			t.Fatal(err)
		}
		id, err := RecipientID(key)
		if err != nil || id != vector.ID {
			t.Fatalf("recipient ID mismatch: %v", err)
		}
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := RecipientID(make([]byte, n)); err == nil {
			t.Fatal("accepted wrong key length")
		}
	}
}

func TestRecipientMismatchNeverReachesHandler(t *testing.T) {
	s := testServer(t)
	for _, ids := range [][]string{{"wrong"}, {""}, {"a", "b"}} {
		request, _ := encryptedRequest(t, s, http.MethodPost, "/prove/transfer_2_2", []byte(`{}`))
		request.Header[http.CanonicalHeaderKey(HeaderKeyID)] = ids
		called := false
		recorder := httptest.NewRecorder()
		s.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(recorder, request)
		if called || recorder.Code != 400 {
			t.Fatal("wrong recipient reached handler")
		}
	}
	request, _ := encryptedRequest(t, s, http.MethodPost, "/prove/transfer_2_2", []byte(`{}`))
	id, _ := RecipientID(s.PublicKey())
	request.Header.Set(HeaderKeyID, id)
	called := false
	recorder := httptest.NewRecorder()
	s.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get(HeaderKeyID) != "" {
			t.Error("recipient hint leaked to inner handler")
		}
		w.WriteHeader(200)
	})).ServeHTTP(recorder, request)
	if !called || recorder.Code != 200 {
		t.Fatal("matching recipient rejected")
	}
}
