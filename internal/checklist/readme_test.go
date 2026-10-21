package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var ciFloor = regexp.MustCompile(`(?m)^\s*FLOOR:\s*'([0-9]+(?:\.[0-9]+)?)'\s*$`)

// TestReadmeBadges keeps the README badges honest. The real mappings are
// checked before they are counted, so a row naming a missing test never
// contributes to a green badge, and the coverage badge must show the floor CI
// actually enforces.
func TestReadmeBadges(t *testing.T) {
	root := filepath.Join("..", "..")
	file := filepath.Join(root, "CHECKLIST.md")
	var out bytes.Buffer
	if code := run([]string{"-file", file, root}, &out, &out); code != 0 {
		t.Fatalf("invalid checklist (exit %d):\n%s", code, out.String())
	}
	items, err := parseChecklist(file, func(format string, args ...interface{}) {
		t.Errorf(format, args...)
	})
	if err != nil {
		t.Fatal(err)
	}
	mapped := 0
	for _, it := range items {
		if !it.na {
			mapped++
		}
	}

	ci, err := ioutil.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	m := ciFloor.FindAllSubmatch(ci, -1)
	if len(m) != 1 {
		t.Fatalf("want exactly one FLOOR in ci.yml, found %d", len(m))
	}
	floor, err := strconv.ParseFloat(string(m[0][1]), 64)
	if err != nil {
		t.Fatal(err)
	}
	color := "yellowgreen"
	if floor >= 95 {
		color = "brightgreen"
	}
	pct := strconv.FormatFloat(floor, 'f', -1, 64)

	readme, err := ioutil.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[![CI](https://github.com/rest-mail/go-smtp/actions/workflows/ci.yml/badge.svg)](https://github.com/rest-mail/go-smtp/actions/workflows/ci.yml)",
		fmt.Sprintf("[![Coverage gate: >=%s%%](https://img.shields.io/badge/coverage%%20gate-%%3E%%3D%s%%25-%s)](COVERAGE.md)",
			pct, pct, color),
		fmt.Sprintf("[![Checklist: %d/%d mapped](https://img.shields.io/badge/checklist-%d%%2F%d%%20mapped-blue)](CHECKLIST.md)",
			mapped, len(items), mapped, len(items)),
	} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("stale or missing README badge; want:\n%s", want)
		}
	}
}
