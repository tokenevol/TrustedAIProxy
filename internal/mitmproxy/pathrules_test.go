package mitmproxy

import (
	"strings"
	"testing"
)

func TestCompiledPathRulesMatchExactAndTemplatePaths(t *testing.T) {
	rules, err := CompilePathRules(map[string]PathRule{
		"/":                                      markedRule("root"),
		"/users/{user}/messages":                 markedRule("user-template"),
		"/users/admin/messages":                  markedRule("admin-exact"),
		"/accounts/{account}/agents/{agent}/run": markedRule("multiple-parameters"),
		"/a/static/x":                            markedRule("static-dead-end"),
		"/a/{value}/tail":                        markedRule("parameter-fallback"),
		"/b/static/{value}":                      markedRule("static-precedence"),
		"/b/{value}/tail":                        markedRule("parameter-precedence"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rules.Len(), 8; got != want {
		t.Fatalf("rule count = %d, want %d", got, want)
	}
	tests := map[string]string{
		"/":                                 "root",
		"/users/alice/messages":             "user-template",
		"/users/admin/messages":             "admin-exact",
		"/accounts/acme/agents/primary/run": "multiple-parameters",
		"/a/static/tail":                    "parameter-fallback",
		"/b/static/tail":                    "static-precedence",
	}
	for path, want := range tests {
		t.Run(path, func(t *testing.T) {
			rule, ok := rules.Match(path)
			if !ok {
				t.Fatal("expected path to match")
			}
			if got := rule.Extractor; got != want {
				t.Fatalf("matched rule = %q, want %q", got, want)
			}
		})
	}
	for _, path := range []string{
		"/users//messages",
		"/users/alice/messages/extra",
		"/accounts/acme/agents//run",
		"users/alice/messages",
	} {
		t.Run("no-match "+path, func(t *testing.T) {
			if _, ok := rules.Match(path); ok {
				t.Fatal("expected path not to match")
			}
		})
	}
}

func TestCompilePathRulesRejectsEquivalentTemplates(t *testing.T) {
	_, err := CompilePathRules(map[string]PathRule{
		"/users/{user_id}/messages": markedRule("first"),
		"/users/{name}/messages":    markedRule("second"),
	})
	if err == nil || !strings.Contains(err.Error(), "match the same paths") {
		t.Fatalf("error = %v", err)
	}
}

func TestCompilePathRulesRejectsInvalidPatterns(t *testing.T) {
	patterns := []string{
		"",
		"relative/{name}",
		"/users/{name}?active=true",
		"/users/{}",
		"/users/{9name}",
		"/users/{bad-name}",
		"/users/{name",
		"/users/name}",
		"/users/prefix-{name}",
		"/users/{name}-suffix",
		"/users/{{name}}",
	}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			if _, err := CompilePathRules(map[string]PathRule{pattern: markedRule("invalid")}); err == nil {
				t.Fatal("expected pattern to be rejected")
			}
		})
	}
}

func markedRule(marker string) PathRule {
	return PathRule{Extractor: marker}
}
