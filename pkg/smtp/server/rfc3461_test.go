package server

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rest-mail/go-smtp/pkg/smtp"
	"github.com/rest-mail/go-smtp/pkg/smtp/internal/wire"
)

// RFC 3461 section 4.1 uses RFC 822 section 2.7's 1# list: conditions
// can repeat and null elements do not count. NEVER is a separate alternative.
const notifyConditionGrammar = `[Ss][Uu][Cc][Cc][Ee][Ss][Ss]|[Ff][Aa][Ii][Ll][Uu][Rr][Ee]|[Dd][Ee][Ll][Aa][Yy]`

// Spell ASCII case pairs explicitly: regexp's (?i) also accepts Unicode long s.
var notifyGrammar = regexp.MustCompile(`^(?:[Nn][Ee][Vv][Ee][Rr]|,*(?:` +
	notifyConditionGrammar + `)(?:,+(?:` + notifyConditionGrammar + `))*,*)$`)

// checklist: DSN-SYNTAX-01 DSN-SYNTAX-02
func FuzzRFC3461Notify(f *testing.F) {
	for _, seed := range []string{"NEVER", "never", "SUCCESS", "sUcCeSs,failure,DELAY", "SUCCESS,SUCCESS", ",SUCCESS,,FAILURE,", "", ",,,", "NEVER,", "NEVER,NEVER", "NEVER,FAILURE", "SUCCESS,BOGUS", "SUCCESS\x00", "SUCCESS,\tFAILURE", "ſUCCESS", "SUCCESS，FAILURE"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxParserFuzzInput {
			t.Skip()
		}
		got, err := parseDSNNotify(input)
		if valid := notifyGrammar.MatchString(input); valid != (err == nil) {
			t.Fatalf("parseDSNNotify(%q)=%v,%v; grammar valid=%v", input, got, err, valid)
		}
		if err != nil {
			return
		}
		if err := wire.CheckNotifySet(got); err != nil {
			t.Fatalf("invalid normalized API flags %v: %v", got, err)
		}
		seen := map[smtp.DSNNotify]bool{}
		upper := strings.ToUpper(input)
		for _, flag := range got {
			if seen[flag] || !strings.Contains(upper, string(flag)) {
				t.Fatalf("unexpected or duplicate flag %q in %v", flag, got)
			}
			seen[flag] = true
		}
		for _, flag := range []smtp.DSNNotify{smtp.DSNNotifyNever, smtp.DSNNotifySuccess, smtp.DSNNotifyFailure, smtp.DSNNotifyDelayed} {
			if strings.Contains(upper, string(flag)) != seen[flag] {
				t.Fatalf("lost flag %q in %q: %v", flag, input, got)
			}
		}
		canonical := make([]string, len(got))
		for i, flag := range got {
			canonical[i] = string(flag)
		}
		again, err := parseDSNNotify(strings.Join(canonical, ","))
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("normalization not stable: %v -> %v, %v", got, again, err)
		}
	})
}
