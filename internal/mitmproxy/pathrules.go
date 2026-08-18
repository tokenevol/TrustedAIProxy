package mitmproxy

import (
	"fmt"
	"strings"
)

// CompiledPathRules matches exact paths and single-segment path parameters.
// It is built once during startup and then used for concurrent lookups.
type CompiledPathRules struct {
	exact     map[string]PathRule
	templates *pathRuleNode
	count     int
}

type pathRuleNode struct {
	static    map[string]*pathRuleNode
	parameter *pathRuleNode
	rule      *PathRule
	pattern   string
}

// CompilePathRules validates and compiles configured path rules. A parameter
// must occupy a complete segment, for example /deployments/{deployment}/chat.
func CompilePathRules(configured map[string]PathRule) (*CompiledPathRules, error) {
	compiled := &CompiledPathRules{
		exact:     make(map[string]PathRule),
		templates: &pathRuleNode{},
		count:     len(configured),
	}
	for pattern, rule := range configured {
		segments, template, err := parsePathPattern(pattern)
		if err != nil {
			return nil, err
		}
		if !template {
			compiled.exact[pattern] = clonePathRule(rule)
			continue
		}

		node := compiled.templates
		for _, segment := range segments {
			if isParameterSegment(segment) {
				if node.parameter == nil {
					node.parameter = &pathRuleNode{}
				}
				node = node.parameter
				continue
			}
			if node.static == nil {
				node.static = make(map[string]*pathRuleNode)
			}
			if node.static[segment] == nil {
				node.static[segment] = &pathRuleNode{}
			}
			node = node.static[segment]
		}
		if node.rule != nil {
			return nil, fmt.Errorf("path templates %q and %q match the same paths", node.pattern, pattern)
		}
		ruleCopy := clonePathRule(rule)
		node.rule = &ruleCopy
		node.pattern = pattern
	}
	return compiled, nil
}

// Len returns the number of configured rules.
func (r *CompiledPathRules) Len() int {
	if r == nil {
		return 0
	}
	return r.count
}

// Match returns the rule for an actual URL path. Exact rules take precedence;
// template matching prefers a static segment and falls back to a parameter.
func (r *CompiledPathRules) Match(path string) (PathRule, bool) {
	if r == nil || path == "" || path[0] != '/' {
		return PathRule{}, false
	}
	if rule, ok := r.exact[path]; ok {
		return rule, true
	}
	rule := matchTemplate(r.templates, splitPath(path), 0)
	if rule == nil {
		return PathRule{}, false
	}
	return *rule, true
}

func matchTemplate(node *pathRuleNode, segments []string, index int) *PathRule {
	if node == nil {
		return nil
	}
	if index == len(segments) {
		return node.rule
	}
	segment := segments[index]
	if child := node.static[segment]; child != nil {
		if rule := matchTemplate(child, segments, index+1); rule != nil {
			return rule
		}
	}
	if segment != "" && node.parameter != nil {
		return matchTemplate(node.parameter, segments, index+1)
	}
	return nil
}

func parsePathPattern(pattern string) ([]string, bool, error) {
	if pattern == "" || pattern[0] != '/' || strings.ContainsAny(pattern, "?#\r\n") {
		return nil, false, fmt.Errorf("invalid request path %q: use a URL path without query or fragment", pattern)
	}
	segments := splitPath(pattern)
	template := false
	for _, segment := range segments {
		hasBrace := strings.ContainsAny(segment, "{}")
		if !hasBrace {
			continue
		}
		if !isParameterSegment(segment) {
			return nil, false, fmt.Errorf("invalid request path template %q: parameters must be complete segments such as {name}", pattern)
		}
		name := segment[1 : len(segment)-1]
		if !validParameterName(name) {
			return nil, false, fmt.Errorf("invalid parameter name %q in request path template %q", name, pattern)
		}
		template = true
	}
	return segments, template, nil
}

func splitPath(path string) []string {
	if path == "/" {
		return nil
	}
	return strings.Split(path[1:], "/")
}

func isParameterSegment(segment string) bool {
	return len(segment) >= 2 && segment[0] == '{' && segment[len(segment)-1] == '}' && strings.Count(segment, "{") == 1 && strings.Count(segment, "}") == 1
}

func validParameterName(name string) bool {
	if name == "" {
		return false
	}
	if !isASCIILetter(name[0]) && name[0] != '_' {
		return false
	}
	for index := 1; index < len(name); index++ {
		character := name[index]
		if !isASCIILetter(character) && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func isASCIILetter(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
}

func clonePathRule(rule PathRule) PathRule {
	return rule
}
