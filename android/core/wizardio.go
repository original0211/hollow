package hollowcore

// NP-1118-62: the guided deployment wizard's facade half (the
// orchestration and the Cloudflare effects live in the wizard
// package; the design increment is
// files/m5/np-1118-62-wizard-android-design-increment.md). This
// file owns what only the facade can own:
//
//   - the token store: the Cloudflare API token sealed through
//     the SAME Keystore SecretBox as the PSK, in its own file
//     (hollow-cftoken.json) so token and pairing lifecycles never
//     interfere; the shell only ever sees the last four digits;
//   - finalize: the wizard's pairing sealed and written through
//     the existing stored-config path, so a wizard-deployed
//     config is indistinguishable from an imported one;
//   - the protector registration: while the VPN service runs it
//     registers its VpnService.protect bridge here, and the
//     wizard's direct dialer protects every socket it opens —
//     wizard traffic never enters the app's own tunnel, with the
//     VPN up or down (design increment 2);
//   - the run state the shell polls (500 ms): current step plus
//     the final wizard.Result verbatim.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"hollow/androidcore/wizard"
)

const cfTokenFileName = "hollow-cftoken.json"

type cfTokenRecord struct {
	TokenEnc  string `json:"tokenEnc"`
	AccountID string `json:"accountId,omitempty"`
}

// --- protector registration ---

var wizardMu sync.Mutex
var wizardProtector Protector

// WizardSetProtector registers the protect bridge the wizard's
// direct dialer uses (the VPN service calls this while it runs).
func WizardSetProtector(p Protector) {
	wizardMu.Lock()
	defer wizardMu.Unlock()
	wizardProtector = p
}

// WizardClearProtector drops the registration (service stopped:
// no TUN exists, so the wizard dials plain — still direct).
func WizardClearProtector() {
	wizardMu.Lock()
	defer wizardMu.Unlock()
	wizardProtector = nil
}

func currentWizardDialer() *wizard.DirectDialer {
	wizardMu.Lock()
	defer wizardMu.Unlock()
	d := &wizard.DirectDialer{}
	if wizardProtector != nil {
		d.Protector = wizardProtector
	}
	return d
}

// --- token store ---

func cfTokenPath() string { return filepath.Join(pairingDir, cfTokenFileName) }

func readCFTokenRecord() (*cfTokenRecord, error) {
	raw, err := os.ReadFile(cfTokenPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec cfTokenRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, errors.New("stored cf token unreadable")
	}
	return &rec, nil
}

func writeCFTokenRecord(rec *cfTokenRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp := cfTokenPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cfTokenPath())
}

func storeCFToken(token, accountID string) error {
	if pairingBox == nil {
		return errors.New("pairing storage not initialized")
	}
	enc, err := pairingBox.Seal([]byte(token))
	if err != nil {
		return err
	}
	return writeCFTokenRecord(&cfTokenRecord{TokenEnc: enc, AccountID: accountID})
}

func loadCFToken() (string, *cfTokenRecord, error) {
	rec, err := readCFTokenRecord()
	if err != nil || rec == nil {
		return "", rec, err
	}
	if pairingBox == nil {
		return "", rec, errors.New("pairing storage not initialized")
	}
	plain, err := pairingBox.Open(rec.TokenEnc)
	if err != nil {
		return "", rec, err
	}
	return string(plain), rec, nil
}

// WizardTokenStatusJSON reports {hasToken, tail} — the shell
// never sees the token itself, only its last four characters.
func WizardTokenStatusJSON() string {
	rec, err := readCFTokenRecord()
	out := map[string]any{"hasToken": false, "tail": nil}
	if err == nil && rec != nil && rec.TokenEnc != "" {
		out["hasToken"] = true
		if tok, _, err := loadCFToken(); err == nil && len(tok) >= 4 {
			out["tail"] = tok[len(tok)-4:]
		}
	}
	raw, _ := json.Marshal(out)
	return string(raw)
}

// WizardDeleteToken removes the stored token (the deployed
// Worker is unaffected, exactly as the copy promises).
func WizardDeleteToken() error {
	err := os.Remove(cfTokenPath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// --- run state ---

type wizardRunState struct {
	Running   bool            `json:"running"`
	Step      string          `json:"step,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	AccountID string          `json:"-"`
	Token     string          `json:"-"`
}

var wizardState = &wizardRunState{}

// WizardStateJSON is the shell's poll surface for a run.
func WizardStateJSON() string {
	wizardMu.Lock()
	defer wizardMu.Unlock()
	raw, _ := json.Marshal(wizardState)
	return string(raw)
}

type wizardStartInput struct {
	Token     string `json:"token"`
	AccountID string `json:"accountId"`
}

// WizardStartJSON starts a wizard run in the background and
// returns immediately; progress and the outcome arrive through
// WizardStateJSON. An empty token means "use the stored token".
func WizardStartJSON(inputJSON string) (string, error) {
	var in wizardStartInput
	if inputJSON != "" {
		if err := json.Unmarshal([]byte(inputJSON), &in); err != nil {
			return "", err
		}
	}
	token := in.Token
	if token == "" {
		stored, _, err := loadCFToken()
		if err != nil {
			return "", err
		}
		token = stored
	}
	if token == "" {
		return "", errors.New("no cloudflare token given or stored")
	}
	wizardMu.Lock()
	if wizardState.Running {
		wizardMu.Unlock()
		return "", errors.New("a wizard run is already in progress")
	}
	wizardState.Running = true
	wizardState.Step = ""
	wizardState.Result = nil
	wizardState.AccountID = in.AccountID
	wizardState.Token = token
	wizardMu.Unlock()

	go runWizardBackground(token, in.AccountID)
	return `{"started":true}`, nil
}

func runWizardBackground(token, accountID string) {
	deps := wizard.NewEffects(currentWizardDialer(), token)
	deps.OnTokenVerified = func(tok string, account wizard.Account) {
		// The token proved itself: persist it (sealed) so a later
		// failure still leaves one-tap retry/update, mirroring the
		// Windows onTokenVerified hook. A storage failure never
		// fails the deployment.
		_ = storeCFToken(tok, account.ID)
	}
	deps.Finalize = func(p wizard.Pairing, account wizard.Account) error {
		if pairingBox == nil {
			return errors.New("pairing storage not initialized")
		}
		enc, err := pairingBox.Seal(p.PSK)
		if err != nil {
			return err
		}
		return writeStored(&storedConfig{
			WSURL: p.WorkerURL, KeyID: p.KeyID,
			MetaPath: p.MetaPath, EdgesPath: p.EdgesPath,
			PSKEnc: enc,
		})
	}
	deps.Progress = func(step, state string) {
		if state != "start" {
			return
		}
		wizardMu.Lock()
		wizardState.Step = step
		wizardMu.Unlock()
	}
	result := wizard.RunWizard(deps, wizard.Input{Token: token, AccountID: accountID})
	raw, _ := json.Marshal(result)
	wizardMu.Lock()
	wizardState.Running = false
	wizardState.Result = raw
	if result.AccountID != "" {
		wizardState.AccountID = result.AccountID
	}
	wizardMu.Unlock()
}

// WizardDeleteWorkerJSON deletes the wizard-deployed Worker from
// the user's account (the failure page's one-tap cleanup; never
// forced). Uses the run's account when known, else the token
// record's. Synchronous and bounded by the API client timeout;
// the shell calls it off the UI thread.
func WizardDeleteWorkerJSON() (string, error) {
	wizardMu.Lock()
	token, accountID := wizardState.Token, wizardState.AccountID
	wizardMu.Unlock()
	if token == "" || accountID == "" {
		stored, rec, err := loadCFToken()
		if err != nil {
			return "", err
		}
		if token == "" {
			token = stored
		}
		if accountID == "" && rec != nil {
			accountID = rec.AccountID
		}
	}
	if token == "" {
		return "", errors.New("no cloudflare token available")
	}
	if accountID == "" {
		return "", errors.New("no account known for the deployed worker")
	}
	deps := wizard.NewEffects(currentWizardDialer(), token)
	r := wizard.DeleteDeployedWorker(deps.API, accountID)
	raw, _ := json.Marshal(map[string]any{"ok": r.OK, "status": r.Status})
	return string(raw), nil
}
