package wizard

// Discrimination grids for the wizard orchestration
// (NP-1118-62): a scripted fake Cloudflare API drives every
// branch the UI must present — token invalid / forbidden,
// account selection, the subdomain three-state read with the
// NP-1118-43 fail-closed claim gate, deploy/liveness/finalize
// failures, and the delete cleanup. Mirrors the Windows
// deploy-wizard.test.mjs grids one for one where they exist.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeCall struct {
	Method string
	Path   string
	Body   any
}

type fakeAPI struct {
	calls   []fakeCall
	handler func(method, path string, body any) (*APIResult, error)
	puts    int
}

func (f *fakeAPI) api(method, path string, body any) (*APIResult, error) {
	f.calls = append(f.calls, fakeCall{method, path, body})
	if method == "PUT" {
		f.puts++
	}
	return f.handler(method, path, body)
}

func okResult(result string) *APIResult {
	return &APIResult{OK: true, Status: 200, Result: json.RawMessage(result)}
}

func errResult(status int, errs string) *APIResult {
	return &APIResult{OK: false, Status: status, Errors: json.RawMessage(errs)}
}

// baseHandler answers the happy-path script; tests override the
// branches they exercise.
func baseHandler(subdomainStatus int, subdomainResult string) func(string, string, any) (*APIResult, error) {
	return func(method, path string, body any) (*APIResult, error) {
		switch {
		case path == "/user/tokens/verify":
			return okResult(`{"status":"active"}`), nil
		case path == "/accounts":
			return okResult(`[{"id":"acct1","name":"My Account"}]`), nil
		case strings.HasSuffix(path, "/workers/subdomain") && method == "GET":
			if subdomainStatus != 200 {
				return errResult(subdomainStatus, `[{"code":10000,"message":"err"}]`), nil
			}
			return okResult(subdomainResult), nil
		case strings.HasSuffix(path, "/workers/subdomain") && method == "PUT":
			return okResult(`{"subdomain":"claimed"}`), nil
		case strings.HasSuffix(path, "/subdomain") && method == "POST":
			return okResult(`{"enabled":true}`), nil
		}
		return nil, fmt.Errorf("unexpected call %s %s", method, path)
	}
}

func testDeps(f *fakeAPI) Deps {
	// A coupled fake clock: Sleep advances Now, so the liveness
	// loop's deadline arithmetic behaves like real time (a frozen
	// Now would spin the loop forever — the NP-1118-62 grid's
	// first run hung exactly there).
	clock := time.Unix(1_700_000_000, 0)
	return Deps{
		API: f.api,
		DeployScript: func(accountID, scriptName string, bundle []byte, metadata DeployMetadata) (*APIResult, error) {
			f.calls = append(f.calls, fakeCall{"PUT-SCRIPT", accountID + "/" + scriptName, metadata})
			return okResult(`{}`), nil
		},
		ProbeLiveness:     func(p Pairing) LivenessParts { return LivenessParts{Facade: true, Meta: true, Handshake: true} },
		Finalize:          func(p Pairing, a Account) error { return nil },
		RandomBytes:       func(n int) []byte { return make([]byte, n) },
		RandomHex:         func(n int) string { return strings.Repeat("ab", n) },
		DeriveVerifierHex: func(psk []byte) string { return "vhex" },
		Bundle:            func() []byte { return []byte("bundle") },
		Sleep:             func(d time.Duration) { clock = clock.Add(d) },
		Now:               func() time.Time { return clock },
		LivenessWindow:    time.Second,
		LivenessPoll:      100 * time.Millisecond,
	}
}

func TestWizardHappyPathSubdomainSet(t *testing.T) {
	f := &fakeAPI{handler: baseHandler(200, `{"subdomain":"myname"}`)}
	var finalized *Pairing
	deps := testDeps(f)
	deps.Finalize = func(p Pairing, a Account) error { finalized = &p; return nil }
	verified := 0
	deps.OnTokenVerified = func(token string, a Account) { verified++ }
	r := RunWizard(deps, Input{Token: "tok"})
	if !r.OK {
		t.Fatalf("want ok, got %+v", r)
	}
	if r.WorkerURL != "wss://hollow.myname.workers.dev" {
		t.Fatalf("workerUrl = %s", r.WorkerURL)
	}
	if finalized == nil || finalized.MetaPath != "abababababababababababababababab/meta" || finalized.EdgesPath != "abababababababababababababababab/edges" {
		t.Fatalf("finalized pairing wrong: %+v", finalized)
	}
	if verified != 1 {
		t.Fatalf("OnTokenVerified fired %d times, want 1", verified)
	}
	if f.puts != 0 {
		t.Fatalf("claim PUT issued on a set subdomain (%d)", f.puts)
	}
}

func TestWizardTokenInvalid(t *testing.T) {
	f := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
		return errResult(401, `[{"code":1000,"message":"bad token"}]`), nil
	}}
	verified := 0
	deps := testDeps(f)
	deps.OnTokenVerified = func(string, Account) { verified++ }
	r := RunWizard(deps, Input{Token: "bad"})
	if r.OK || r.Code != "TOKEN_INVALID" || r.Step != "verify" {
		t.Fatalf("got %+v", r)
	}
	if verified != 0 {
		t.Fatal("OnTokenVerified must not fire on a failed verify")
	}
	if len(f.calls) != 1 {
		t.Fatalf("calls = %d, want 1 (no further steps)", len(f.calls))
	}
}

func TestWizardTokenForbidden(t *testing.T) {
	f := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
		if path == "/user/tokens/verify" {
			return errResult(403, `[]`), nil
		}
		return okResult(`[]`), nil
	}}
	r := RunWizard(testDeps(f), Input{Token: "tok"})
	if r.OK || r.Code != "TOKEN_FORBIDDEN" {
		t.Fatalf("got %+v", r)
	}
	// Accounts-list forbidden is TOKEN_FORBIDDEN too.
	f2 := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
		if path == "/accounts" {
			return errResult(403, `[]`), nil
		}
		return okResult(`{}`), nil
	}}
	r2 := RunWizard(testDeps(f2), Input{Token: "tok"})
	if r2.OK || r2.Code != "TOKEN_FORBIDDEN" {
		t.Fatalf("accounts variant: got %+v", r2)
	}
}

func TestWizardMultiAccount(t *testing.T) {
	two := func(method, path string, body any) (*APIResult, error) {
		if path == "/accounts" {
			return okResult(`[{"id":"a1","name":"One"},{"id":"a2","name":"Two"}]`), nil
		}
		return baseHandler(200, `{"subdomain":"s"}`)(method, path, body)
	}
	f := &fakeAPI{handler: two}
	r := RunWizard(testDeps(f), Input{Token: "tok"})
	if r.OK || r.Code != "MULTI_ACCOUNT" || len(r.Accounts) != 2 {
		t.Fatalf("got %+v", r)
	}
	// With a selection the run proceeds on the chosen account.
	f2 := &fakeAPI{handler: two}
	deps := testDeps(f2)
	var deployedAccount string
	deps.DeployScript = func(accountID, scriptName string, bundle []byte, metadata DeployMetadata) (*APIResult, error) {
		deployedAccount = accountID
		return okResult(`{}`), nil
	}
	r2 := RunWizard(deps, Input{Token: "tok", AccountID: "a2"})
	if !r2.OK || deployedAccount != "a2" {
		t.Fatalf("selected run: ok=%v deployed=%s", r2.OK, deployedAccount)
	}
	// An unknown selection is NO_ACCOUNT.
	f3 := &fakeAPI{handler: two}
	r3 := RunWizard(testDeps(f3), Input{Token: "tok", AccountID: "nope"})
	if r3.OK || r3.Code != "NO_ACCOUNT" {
		t.Fatalf("unknown selection: got %+v", r3)
	}
}

func TestWizardNoAccount(t *testing.T) {
	f := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
		if path == "/accounts" {
			return okResult(`[]`), nil
		}
		return okResult(`{}`), nil
	}}
	r := RunWizard(testDeps(f), Input{Token: "tok"})
	if r.OK || r.Code != "NO_ACCOUNT" {
		t.Fatalf("got %+v", r)
	}
}

func TestWizardSubdomainUnsetOkClaims(t *testing.T) {
	f := &fakeAPI{handler: baseHandler(200, `{}`)}
	r := RunWizard(testDeps(f), Input{Token: "tok"})
	if !r.OK {
		t.Fatalf("got %+v", r)
	}
	if f.puts != 1 {
		t.Fatalf("claim PUTs = %d, want 1", f.puts)
	}
	// The claimed name is the slug+suffix candidate.
	for _, c := range f.calls {
		if c.Method == "PUT" {
			m := c.Body.(map[string]string)
			if !strings.HasPrefix(m["subdomain"], "my-account-") {
				t.Fatalf("candidate = %s", m["subdomain"])
			}
		}
	}
}

func TestWizardSubdomainUnset404Claims(t *testing.T) {
	f := &fakeAPI{handler: baseHandler(404, "")}
	r := RunWizard(testDeps(f), Input{Token: "tok"})
	if !r.OK || f.puts != 1 {
		t.Fatalf("ok=%v puts=%d (%+v)", r.OK, f.puts, r)
	}
}

// The NP-1118-43 grid: an indeterminate read (5xx / 403 / thrown)
// fails closed with ZERO claim PUTs — a PUT on an account that
// HAS a subdomain would rename it.
func TestWizardSubdomainIndeterminateFailsClosed(t *testing.T) {
	for _, variant := range []string{"500", "403", "throw"} {
		f := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
			if strings.HasSuffix(path, "/workers/subdomain") && method == "GET" {
				if variant == "throw" {
					return nil, errors.New("network down")
				}
				return errResult(map[string]int{"500": 500, "403": 403}[variant], `[]`), nil
			}
			return baseHandler(200, `{"subdomain":"s"}`)(method, path, body)
		}}
		r := RunWizard(testDeps(f), Input{Token: "tok"})
		if r.OK || r.Code != "SUBDOMAIN_FAILED" {
			t.Fatalf("variant %s: got %+v", variant, r)
		}
		if f.puts != 0 {
			t.Fatalf("variant %s: %d claim PUTs issued on an indeterminate read", variant, f.puts)
		}
	}
}

func TestWizardSubdomainClaimExhausted(t *testing.T) {
	f := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
		if method == "PUT" {
			return errResult(400, `[{"code":10000,"message":"taken"}]`), nil
		}
		return baseHandler(200, `{}`)(method, path, body)
	}}
	r := RunWizard(testDeps(f), Input{Token: "tok"})
	if r.OK || r.Code != "SUBDOMAIN_FAILED" {
		t.Fatalf("got %+v", r)
	}
	if f.puts != 3 {
		t.Fatalf("claim attempts = %d, want 3", f.puts)
	}
}

func TestWizardDeployNotEnabled(t *testing.T) {
	f := &fakeAPI{handler: baseHandler(200, `{"subdomain":"s"}`)}
	deps := testDeps(f)
	deps.DeployScript = func(string, string, []byte, DeployMetadata) (*APIResult, error) {
		return errResult(400, `[{"code":10063,"message":"workers not enabled"}]`), nil
	}
	r := RunWizard(deps, Input{Token: "tok"})
	if r.OK || r.Code != "DEPLOY_FAILED" || !r.WorkersNotEnabled {
		t.Fatalf("got %+v", r)
	}
}

func TestWizardLivenessFailureCarriesParts(t *testing.T) {
	f := &fakeAPI{handler: baseHandler(200, `{"subdomain":"s"}`)}
	deps := testDeps(f)
	deps.ProbeLiveness = func(p Pairing) LivenessParts { return LivenessParts{Facade: true, Meta: false, Handshake: true} }
	finalized := false
	deps.Finalize = func(Pairing, Account) error { finalized = true; return nil }
	r := RunWizard(deps, Input{Token: "tok"})
	if r.OK || r.Code != "LIVENESS_FAILED" || r.Parts == nil || r.Parts.Meta {
		t.Fatalf("got %+v", r)
	}
	if finalized {
		t.Fatal("finalize must not run when liveness fails")
	}
}

func TestWizardLivenessSecondPollSucceeds(t *testing.T) {
	f := &fakeAPI{handler: baseHandler(200, `{"subdomain":"s"}`)}
	deps := testDeps(f)
	n := 0
	deps.ProbeLiveness = func(p Pairing) LivenessParts {
		n++
		if n < 2 {
			return LivenessParts{}
		}
		return LivenessParts{Facade: true, Meta: true, Handshake: true}
	}
	r := RunWizard(deps, Input{Token: "tok"})
	if !r.OK || n != 2 {
		t.Fatalf("ok=%v probes=%d", r.OK, n)
	}
}

func TestWizardFinalizeFailure(t *testing.T) {
	f := &fakeAPI{handler: baseHandler(200, `{"subdomain":"s"}`)}
	deps := testDeps(f)
	deps.Finalize = func(Pairing, Account) error { return errors.New("disk full") }
	r := RunWizard(deps, Input{Token: "tok"})
	if r.OK || r.Code != "FINALIZE_FAILED" {
		t.Fatalf("got %+v", r)
	}
}

func TestDeleteDeployedWorker(t *testing.T) {
	f := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
		if method == "DELETE" && strings.HasSuffix(path, "/workers/scripts/hollow") {
			return okResult(`{}`), nil
		}
		return errResult(404, `[]`), nil
	}}
	if r := DeleteDeployedWorker(f.api, "acct1"); !r.OK {
		t.Fatal("delete should succeed")
	}
	f2 := &fakeAPI{handler: func(method, path string, body any) (*APIResult, error) {
		return nil, errors.New("network down")
	}}
	if r := DeleteDeployedWorker(f2.api, "acct1"); r.OK {
		t.Fatal("a thrown delete must report not-ok")
	}
}

func TestBuildDeployMetadataShape(t *testing.T) {
	m := BuildDeployMetadata("vhex", "seg")
	if m.MainModule != "index.js" || m.CompatibilityDate != "2025-10-01" || m.UsageModel != "standard" {
		t.Fatalf("metadata drift: %+v", m)
	}
	if len(m.Bindings) != 2 || m.Bindings[0].Name != "META_SEG" || m.Bindings[1].Name != "PSK_V_HEX" || m.Bindings[1].Text != "vhex" {
		t.Fatalf("bindings drift: %+v", m.Bindings)
	}
}

func TestSubdomainCandidate(t *testing.T) {
	if got := SubdomainCandidate("My Cool Account!", "ab12"); got != "my-cool-account-ab12" {
		t.Fatalf("got %s", got)
	}
	if got := SubdomainCandidate("", "ab12"); got != "hollow-ab12" {
		t.Fatalf("empty name: got %s", got)
	}
}
