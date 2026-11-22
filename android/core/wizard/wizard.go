// Package wizard is the Android port of the guided deployment
// wizard (design NP-1118-41, Windows implementation NP-1118-42/43,
// Android increment NP-1118-62): deploy the user's OWN Hollow
// Worker from inside the app — no console. The six steps mirror
// the verified production deploy procedure (NP-1117-01) and the
// Windows orchestration item for item: verify the token, generate
// the pairing locally, PUT the bundled Worker with both secrets,
// enable the workers.dev subdomain, prove liveness (facade +
// /meta + real handshake, riding out the version-propagation
// lag), and only then persist the config.
//
// Pure orchestration with injected effects, exactly like the JS
// original; cfapi.go provides the real Cloudflare effects and the
// hollowcore facade wires storage. Every step is idempotent — a
// failure names its step and code, changes nothing locally, and
// re-running converges. The token is used only through Deps.API /
// Deps.DeployScript and is never logged or returned.
//
// Failure codes (identical to Windows): TOKEN_INVALID,
// TOKEN_FORBIDDEN (missing a required permission), NO_ACCOUNT,
// MULTI_ACCOUNT (caller picks), DEPLOY_FAILED (with a
// WorkersNotEnabled hint when the API error says so),
// SUBDOMAIN_FAILED, LIVENESS_FAILED (with the per-part results),
// FINALIZE_FAILED.
package wizard

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ScriptName is the fixed Worker script name the wizard deploys
// (a different name space from any operator-owned script).
const ScriptName = "hollow"

// Steps in order, for progress presentation.
var Steps = []string{"verify", "generate", "deploy", "subdomain", "liveness", "finalize"}

// Account is one Cloudflare account as the wizard needs it.
type Account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Pairing is the generated configuration the wizard deploys and,
// on success, persists.
type Pairing struct {
	WorkerURL string `json:"workerUrl"`
	KeyID     int    `json:"keyId"`
	PSK       []byte `json:"-"`
	MetaPath  string `json:"metaPath"`
	EdgesPath string `json:"edgesPath"`
}

// LivenessParts is the per-part liveness verdict (reported
// separately so the copy can say WHAT did not come up).
type LivenessParts struct {
	Facade    bool `json:"facade"`
	Meta      bool `json:"meta"`
	Handshake bool `json:"handshake"`
}

// APIResult is the Cloudflare envelope as the orchestration
// consumes it: OK mirrors the JS side's `res.ok && success`.
type APIResult struct {
	OK     bool
	Status int
	Result json.RawMessage
	Errors json.RawMessage
}

// DeployMetadata is the PUT metadata (shape locked to the
// production deploy procedure).
type DeployMetadata struct {
	MainModule         string          `json:"main_module"`
	CompatibilityDate  string          `json:"compatibility_date"`
	CompatibilityFlags []string        `json:"compatibility_flags"`
	UsageModel         string          `json:"usage_model"`
	Bindings           []DeployBinding `json:"bindings"`
}

// DeployBinding is one secret_text binding.
type DeployBinding struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Text string `json:"text"`
}

// BuildDeployMetadata mirrors the JS buildDeployMetadata.
func BuildDeployMetadata(vHex, metaSeg string) DeployMetadata {
	return DeployMetadata{
		MainModule:         "index.js",
		CompatibilityDate:  "2025-10-01",
		CompatibilityFlags: []string{"nodejs_compat"},
		UsageModel:         "standard",
		Bindings: []DeployBinding{
			{Name: "META_SEG", Type: "secret_text", Text: metaSeg},
			{Name: "PSK_V_HEX", Type: "secret_text", Text: vHex},
		},
	}
}

// Deps are the wizard's injected effects.
type Deps struct {
	// API performs one Cloudflare API call with the run's token.
	API func(method, path string, body any) (*APIResult, error)
	// DeployScript PUTs the bundle with metadata (multipart).
	DeployScript func(accountID, scriptName string, bundle []byte, metadata DeployMetadata) (*APIResult, error)
	// ProbeLiveness runs the three liveness parts for a pairing.
	ProbeLiveness func(p Pairing) LivenessParts
	// Finalize persists the pairing as the current config.
	Finalize func(p Pairing, account Account) error
	// OnTokenVerified fires once the token has proved itself (the
	// caller persists it there); its errors never fail the run.
	OnTokenVerified func(token string, account Account)

	RandomBytes func(n int) []byte
	// RandomHex returns 2n lowercase hex characters from n random bytes.
	RandomHex         func(n int) string
	DeriveVerifierHex func(psk []byte) string
	Bundle            func() []byte
	Sleep             func(d time.Duration)
	Now               func() time.Time
	LivenessWindow    time.Duration // 0 = 180s
	LivenessPoll      time.Duration // 0 = 15s
	Progress          func(step, state string)
}

// Input is one wizard run's user input.
type Input struct {
	Token     string
	AccountID string // empty = auto (single account) or MULTI_ACCOUNT
}

// Result is the run's outcome. On failure OK is false and
// Step/Code/Detail name the failure; Accounts is set for
// MULTI_ACCOUNT, Parts for LIVENESS_FAILED, WorkersNotEnabled for
// the deploy-not-enabled hint.
type Result struct {
	OK                bool           `json:"ok"`
	Step              string         `json:"step,omitempty"`
	Code              string         `json:"code,omitempty"`
	Detail            string         `json:"detail,omitempty"`
	WorkersNotEnabled bool           `json:"workersNotEnabled,omitempty"`
	Accounts          []Account      `json:"accounts,omitempty"`
	Parts             *LivenessParts `json:"parts,omitempty"`
	WorkerURL         string         `json:"workerUrl,omitempty"`
	AccountID         string         `json:"accountId,omitempty"`
	AccountName       string         `json:"accountName,omitempty"`
	Subdomain         string         `json:"subdomain,omitempty"`
}

func fail(step, code, detail string) *Result {
	return &Result{OK: false, Step: step, Code: code, Detail: detail}
}

// SubdomainCandidate mirrors the JS subdomainCandidate: a
// claimable workers.dev subdomain from the account name —
// lowercase slug + a short random suffix.
func SubdomainCandidate(accountName, suffix string) string {
	slug := strings.ToLower(accountName)
	if slug == "" {
		slug = "hollow"
	}
	slug = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(slug, "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 24 {
		slug = slug[:24]
	}
	if slug == "" {
		slug = "hollow"
	}
	return slug + "-" + suffix
}

var workersNotEnabledRe = regexp.MustCompile(`(?i)not.*enabled|workers.*disabled|10063`)

// RunWizard executes the six steps. It never returns an error:
// every outcome is a Result, exactly like the JS runWizard.
func RunWizard(deps Deps, input Input) *Result {
	progress := deps.Progress
	if progress == nil {
		progress = func(string, string) {}
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	sleep := deps.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	window := deps.LivenessWindow
	if window == 0 {
		window = 180 * time.Second
	}
	poll := deps.LivenessPoll
	if poll == 0 {
		poll = 15 * time.Second
	}

	// Step 0 — verify the token and resolve the account.
	progress("verify", "start")
	ver, err := deps.API("GET", "/user/tokens/verify", nil)
	if err != nil {
		progress("verify", "fail")
		return fail("verify", "TOKEN_INVALID", fmt.Sprintf("令牌校验请求失败：%v", err))
	}
	if !ver.OK {
		progress("verify", "fail")
		if ver.Status == 403 {
			return fail("verify", "TOKEN_FORBIDDEN", fmt.Sprintf("令牌被 Cloudflare 拒绝（HTTP %d）", ver.Status))
		}
		return fail("verify", "TOKEN_INVALID", fmt.Sprintf("令牌被 Cloudflare 拒绝（HTTP %d）", ver.Status))
	}
	accs, err := deps.API("GET", "/accounts", nil)
	if err != nil {
		progress("verify", "fail")
		return fail("verify", "TOKEN_INVALID", fmt.Sprintf("账号列表请求失败：%v", err))
	}
	if !accs.OK {
		progress("verify", "fail")
		return fail("verify", "TOKEN_FORBIDDEN", fmt.Sprintf("读不到账号列表（HTTP %d）——令牌缺 Account Settings: Read？", accs.Status))
	}
	var list []Account
	if len(accs.Result) > 0 {
		_ = json.Unmarshal(accs.Result, &list)
	}
	if len(list) == 0 {
		progress("verify", "fail")
		return fail("verify", "NO_ACCOUNT", "该令牌下没有任何 Cloudflare 账号")
	}
	if input.AccountID == "" && len(list) > 1 {
		progress("verify", "fail")
		r := fail("verify", "MULTI_ACCOUNT", "令牌下有多个账号，请选择部署目标")
		r.Accounts = list
		return r
	}
	account := list[0]
	if input.AccountID != "" {
		found := false
		for _, a := range list {
			if a.ID == input.AccountID {
				account, found = a, true
				break
			}
		}
		if !found {
			progress("verify", "fail")
			return fail("verify", "NO_ACCOUNT", "所选账号不在该令牌下")
		}
	}
	progress("verify", "done")
	// The token proved itself — the caller persists it now so a
	// later failure still leaves one-click retry/update possible.
	if deps.OnTokenVerified != nil {
		func() {
			defer func() { _ = recover() }()
			deps.OnTokenVerified(input.Token, account)
		}()
	}

	// Step 1 — generate the pairing locally.
	progress("generate", "start")
	psk := deps.RandomBytes(32)
	metaSeg := deps.RandomHex(16)
	vHex := deps.DeriveVerifierHex(psk)
	progress("generate", "done")

	// Step 2 — deploy the bundled Worker with both secrets.
	progress("deploy", "start")
	r, err := deps.DeployScript(account.ID, ScriptName, deps.Bundle(), BuildDeployMetadata(vHex, metaSeg))
	if err != nil {
		progress("deploy", "fail")
		return fail("deploy", "DEPLOY_FAILED", fmt.Sprintf("部署请求失败：%v", err))
	}
	if !r.OK {
		progress("deploy", "fail")
		text := string(r.Errors)
		if text == "" || text == "null" {
			raw, _ := json.Marshal(r)
			text = string(raw)
		}
		if len(text) > 240 {
			text = text[:240]
		}
		res := fail("deploy", "DEPLOY_FAILED", fmt.Sprintf("部署被拒（HTTP %d）：%s", r.Status, text))
		res.WorkersNotEnabled = workersNotEnabledRe.MatchString(string(r.Errors))
		return res
	}
	progress("deploy", "done")

	// Step 3 — workers.dev subdomain: read the account subdomain,
	// claim one ONLY when the read definitively says "unset", and
	// enable the script's. PUT /workers/subdomain on an account
	// that HAS a subdomain RENAMES it (every existing workers.dev
	// address breaks), so the claim ring is gated on the attested
	// unset forms only: an ok response carrying no subdomain, or
	// HTTP 404. A thrown read or any other status (403/5xx/…)
	// fails closed with retry guidance and never issues a PUT
	// (NP-1118-43, carried over verbatim).
	progress("subdomain", "start")
	var subName string
	readForm := "indeterminate"
	{
		sr, err := deps.API("GET", "/accounts/"+account.ID+"/workers/subdomain", nil)
		if err != nil {
			progress("subdomain", "fail")
			return fail("subdomain", "SUBDOMAIN_FAILED", fmt.Sprintf("子域读取请求失败：%v——稍后重试向导即可；读不清时向导不会改动任何子域设置", err))
		}
		if sr.OK {
			var sub struct {
				Subdomain string `json:"subdomain"`
			}
			_ = json.Unmarshal(sr.Result, &sub)
			if sub.Subdomain != "" {
				subName, readForm = sub.Subdomain, "set"
			} else {
				readForm = "unset"
			}
		} else if sr.Status == 404 {
			readForm = "unset"
		} else {
			progress("subdomain", "fail")
			return fail("subdomain", "SUBDOMAIN_FAILED", fmt.Sprintf("子域读取失败（HTTP %d）——稍后重试向导即可；读不清时向导不会改动任何子域设置", sr.Status))
		}
	}
	if subName == "" && readForm == "unset" {
		for attempt := 0; attempt < 3 && subName == ""; attempt++ {
			candidate := SubdomainCandidate(account.Name, deps.RandomHex(2))
			cr, err := deps.API("PUT", "/accounts/"+account.ID+"/workers/subdomain", map[string]string{"subdomain": candidate})
			if err == nil && cr.OK {
				subName = candidate
			}
		}
		if subName == "" {
			progress("subdomain", "fail")
			return fail("subdomain", "SUBDOMAIN_FAILED", "账号尚无 workers.dev 子域且自动领取失败——请在 Cloudflare 控制台的 Workers 页面领取一次子域后重试")
		}
	}
	{
		er, err := deps.API("POST", "/accounts/"+account.ID+"/workers/scripts/"+ScriptName+"/subdomain", map[string]bool{"enabled": true})
		if err != nil {
			progress("subdomain", "fail")
			return fail("subdomain", "SUBDOMAIN_FAILED", fmt.Sprintf("脚本子域启用请求失败：%v", err))
		}
		if !er.OK {
			progress("subdomain", "fail")
			return fail("subdomain", "SUBDOMAIN_FAILED", fmt.Sprintf("脚本子域启用被拒（HTTP %d）", er.Status))
		}
	}
	progress("subdomain", "done")
	workerURL := "wss://" + ScriptName + "." + subName + ".workers.dev"
	pairing := Pairing{
		WorkerURL: workerURL, KeyID: 1, PSK: psk,
		MetaPath: metaSeg + "/meta", EdgesPath: metaSeg + "/edges",
	}

	// Step 4 — liveness: facade + /meta + real handshake, riding
	// out the post-deploy propagation lag (measured ~3 min worst
	// case) before declaring failure; the parts are reported
	// separately so the copy can say WHAT did not come up.
	progress("liveness", "start")
	deadline := now().Add(window)
	var last LivenessParts
	for {
		last = deps.ProbeLiveness(pairing)
		if last.Facade && last.Meta && last.Handshake {
			break
		}
		if !now().Before(deadline) {
			progress("liveness", "fail")
			res := fail("liveness", "LIVENESS_FAILED", "部署完成但验活未通过——Worker 已在账号里，可稍后重试向导（会直接收敛到验活）")
			parts := last
			res.Parts = &parts
			return res
		}
		sleep(poll)
	}
	progress("liveness", "done")

	// Step 5 — persist as the current config (the caller connects).
	progress("finalize", "start")
	if err := deps.Finalize(pairing, account); err != nil {
		progress("finalize", "fail")
		return fail("finalize", "FINALIZE_FAILED", fmt.Sprintf("配置落盘失败：%v——Worker 已部署且验活通过，可用手动导入接回", err))
	}
	progress("finalize", "done")

	return &Result{OK: true, WorkerURL: workerURL, AccountID: account.ID, AccountName: account.Name, Subdomain: subName}
}

// DeleteDeployedWorker is the one-click cleanup offered on the
// failure page (never forced): delete the wizard's script from
// the user's own account.
func DeleteDeployedWorker(api func(method, path string, body any) (*APIResult, error), accountID string) *APIResult {
	r, err := api("DELETE", "/accounts/"+accountID+"/workers/scripts/"+ScriptName, nil)
	if err != nil {
		return &APIResult{OK: false, Errors: json.RawMessage(fmt.Sprintf("%q", err.Error()))}
	}
	return r
}
