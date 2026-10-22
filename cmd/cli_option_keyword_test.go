package cmd

// Tests for the mapping between the configuration keywords of the registered
// option parsers (the auth plugins) and the option names serving them.
//
// Two parsers claim the IdentityFile keyword: the privkey plugin (a private
// key file) and the agent plugin (a public key file). The option parsers
// live in a map, so a naive iteration made the winner - and with it the
// behaviour of -i and -o IdentityFile= - change from run to run: the flag
// worked only half of the time. The ssh(1) canon settles it: IdentityFile
// names a private key file, so the privkey plugin owns the keyword.

import (
	"testing"

	client_config "github.com/francoismichel/ssh3/client/config"
)

// fakeOptionParser is a minimal option parser carrying a config keyword.
type fakeOptionParser struct {
	flagName string
	keyword  string
}

func (p *fakeOptionParser) FlagName() string { return p.flagName }

func (p *fakeOptionParser) IsBoolFlag() bool { return false }

func (p *fakeOptionParser) OptionConfigName() string { return p.keyword }

func (p *fakeOptionParser) Usage() string { return "" }

func (p *fakeOptionParser) Parse([]string) (client_config.Option, error) { return nil, nil }

func TestOptionParsersByKeywordIsDeterministic(t *testing.T) {
	parsers := map[client_config.OptionName]client_config.CLIOptionParser{
		"pubkey-for-agent": &fakeOptionParser{flagName: "pubkey-for-agent", keyword: "IdentityFile"},
		"privkey":          &fakeOptionParser{flagName: "privkey", keyword: "IdentityFile"},
	}

	// the map iteration order changes between runs: the mapping must not
	for i := 0; i < 32; i++ {
		byKeyword := optionParsersByKeyword(parsers)
		got, ok := byKeyword["identityfile"]
		if !ok {
			t.Fatal("the identityfile keyword is not mapped to any option")
		}
		if got != "privkey" {
			t.Fatalf("the identityfile keyword is served by %q, want %q", got, "privkey")
		}
	}
}

func TestOptionParsersByKeywordKeepsUniqueKeywords(t *testing.T) {
	parsers := map[client_config.OptionName]client_config.CLIOptionParser{
		"pubkey-for-agent": &fakeOptionParser{flagName: "pubkey-for-agent", keyword: "IdentityFile"},
		"privkey":          &fakeOptionParser{flagName: "privkey", keyword: "IdentityFile"},
		"other":            &fakeOptionParser{flagName: "other", keyword: "OtherKeyword"},
	}

	byKeyword := optionParsersByKeyword(parsers)
	if len(byKeyword) != 2 {
		t.Fatalf("the keyword map holds %d entries, want 2: %v", len(byKeyword), byKeyword)
	}
	if byKeyword["otherkeyword"] != "other" {
		t.Fatalf("the otherkeyword keyword is served by %q, want %q", byKeyword["otherkeyword"], "other")
	}
}
