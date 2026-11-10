package restapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestOpenAPIMatchesRoutes keeps docs/openapi.yaml in sync with the
// registered routes: every documented path must be routed to its own
// pattern, and every route must be documented.
func TestOpenAPIMatchesRoutes(t *testing.T) {
	spec, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var documented []string
	for _, m := range regexp.MustCompile(`(?m)^  (/\S*):$`).FindAllStringSubmatch(string(spec), -1) {
		documented = append(documented, m[1])
	}
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	var routed []string
	for _, m := range regexp.MustCompile(`HandleFunc\("GET (/\S*)"`).FindAllStringSubmatch(string(src), -1) {
		routed = append(routed, m[1])
	}
	slices.Sort(documented)
	slices.Sort(routed)
	if !slices.Equal(documented, routed) {
		t.Fatalf("spec paths %v != routes %v", documented, routed)
	}

	a := &API{mux: http.NewServeMux()}
	a.routes()
	fill := strings.NewReplacer("{mailbox}", "INBOX", "{uid}", "1", "{index}", "0")
	for _, p := range documented {
		_, pattern := a.mux.Handler(httptest.NewRequest("GET", fill.Replace(p), nil))
		if pattern != "GET "+p {
			t.Errorf("GET %s is routed to %q", p, pattern)
		}
	}
}
