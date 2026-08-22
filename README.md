# ThreatScope

**ThreatScope** is a Streamlit-based Threat Intelligence & SOC Investigation
platform: an IOC (Indicator of Compromise) investigation tool, a log
analyzer, and a file/malware scanner, with MITRE ATT&CK mapping and
persisted investigation history.

**Live app:** https://threatscope-zfdrvh6mdqrzpc5ut3hyjs.streamlit.app/
**Author:** Olawatosin Deborah Ajinomisan — Cybersecurity Analyst | SOC Enthusiast | Threat Intelligence Researcher — [GitHub](https://github.com/ajinotosin-cyber)

---

## Features that genuinely work

### IOC Investigation
Enter an IPv4 address, domain, `http(s)` URL, or MD5/SHA1/SHA256 hash.
ThreatScope detects the IOC type, queries only the providers that support
that type (AbuseIPDB, which is IP-only, is never called with a
domain/URL/hash), and returns a structured verdict: classification,
severity, confidence, per-provider status, and — where defensible — a
MITRE ATT&CK mapping. A provider failure or missing key is always shown
honestly (`PROVIDERS UNAVAILABLE`, `NOT_CONFIGURED`, etc.) and never
silently reported as "Safe."

### Log Analysis
Upload `.txt`, `.log`, `.csv`, or `.json` (array or JSON-lines) log files.
Regex-based detection flags brute-force activity, port scanning,
privilege-escalation attempts, and malware indicators per line/record,
extracts candidate IPv4 IOCs, and maps each finding category to a MITRE
ATT&CK technique where one is defensible. Malformed or unsupported files
are reported as a parse failure, not silently ignored.

### File Analysis
Upload any file to get SHA-256/MD5 hashes, file metadata, a suspicious
-extension heuristic, local YARA rule matching (if `yara-python` and
`rules/malware_rules.yar` are both available), and optional VirusTotal
hash-reputation enrichment if a VirusTotal key is configured. Local
heuristics are explicitly labeled as not equivalent to an antivirus
verdict — the app never returns "Safe" purely because no local check
fired; the honest status in that case is `UNKNOWN`.

### MITRE ATT&CK Mapping
A dedicated page listing every technique mapping currently defined for
log findings and IOC classifications, each with its tactic and rationale.
Mappings are deliberately limited to relationships that are actually
defensible from what the app observes — not every finding gets one.

### Investigation History & Dashboard
Every IOC/log/file analysis is persisted to a local SQLite database
(`data/threatscope.db`, git-ignored). The Dashboard's metrics (total
investigations, critical/high findings, suspicious IOCs) and charts are
computed directly from that stored data — nothing increments artificially,
and the counts survive a page refresh.

### Provider Status (Settings page)
Shows Connected / Not configured / Invalid key / Rate limited for
VirusTotal, AbuseIPDB, and OTX, plus whether the local YARA engine is
ready — without ever displaying key values.

---

## Architecture

```
app.py              Streamlit UI — 7 pages (Dashboard, IOC Investigation,
                     Log Analysis, File Analysis, MITRE ATT&CK,
                     Investigation History, Settings)
config.py            Credential loading: Streamlit secrets -> env var,
                     single canonical name per credential
api_client.py         Shared HTTP layer: timeouts, explicit error statuses,
                     success-only caching, used by every provider call
ioc_analysis.py       IOC type detection/validation + investigation pipeline
log_parser.py         Log parsing (.txt/.log/.csv/.json) + pattern detection
malware_scan.py        File hashing, heuristics, YARA + VirusTotal enrichment
yara_engine.py         Local YARA rule compilation/matching (graceful fallback)
mitre_mapper.py        MITRE ATT&CK technique mappings for findings/IOCs
db.py                 SQLite persistence for investigation history
train_model.py         Standalone offline script — NOT used by the app (see below)
rules/malware_rules.yar   YARA rule used by yara_engine.py
models/model.pkl        Pre-trained RandomForest artifact — NOT used by the app
Dataset/                CIC-IDS2017 training data (used only by train_model.py)
samples/                 Example log file for manually testing Log Analysis
tests/                  Unit tests + Streamlit AppTest end-to-end tests
```

## Technologies used

Python, Streamlit, Pandas, Plotly, `requests`, `python-dotenv`,
`yara-python`. See `requirements.txt` for the exact runtime dependency set
(pruned — see "Requirements audit" below).

## API providers

| Provider | Used for | Required? |
|---|---|---|
| VirusTotal | IP/domain/URL/hash reputation | Yes, for IOC & file enrichment |
| AbuseIPDB | IP abuse confidence score | Yes, for IP investigations |
| AlienVault OTX | Supplementary IP/domain enrichment | **Optional** — app runs fully without it |

---

## Local installation

```bash
git clone https://github.com/ajinotosin-cyber/ThreatScope.git
cd ThreatScope
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and paste your own keys — see "Environment variable setup"
streamlit run app.py
```

### Environment variable setup

Copy `.env.example` to `.env` and fill in your own keys:

```
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
OTX_API_KEY=optional_otx_key_here
```

`.env` is git-ignored — it is never committed. `OTX_API_KEY` may be left
unset; OTX enrichment will simply show as "Not configured" and every other
feature continues to work normally.

### Streamlit Cloud Secrets setup

In production, do **not** rely on a `.env` file. In the Streamlit Cloud
dashboard for this app, go to **Settings → Secrets** and paste:

```toml
VIRUSTOTAL_API_KEY = "your_virustotal_key_here"
ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
OTX_API_KEY = "optional_otx_key_here"
```

(A local template for this is at `.streamlit/secrets.toml.example` — do
not create a real `.streamlit/secrets.toml` file in the repo.)
`config.py` checks `st.secrets` first and falls back to environment
variables automatically, so the same codebase works in both places.

---

## How IOC analysis works

1. `ioc_analysis.detect_ioc_type()` classifies the input as IPv4, Domain,
   URL, or an MD5/SHA1/SHA256 hash using strict format validation — an
   unrecognized value is rejected up front as `INVALID IOC` and no
   provider is ever called with it.
2. Only the providers that support that IOC type are queried (e.g.
   AbuseIPDB — an IP-only API — is never called for a domain, URL, or
   hash; this was a real bug in the previous version).
3. Each provider call goes through `api_client.py`, which enforces a
   timeout and maps every possible outcome (success, invalid key, rate
   limit, not found, network error, malformed response) to an explicit
   status.
4. `ioc_analysis.investigate()` aggregates provider results into one of
   four overall statuses — `VALID RESULT`, `NO DATA FOUND`,
   `INVALID IOC`, or `PROVIDERS UNAVAILABLE` — and only computes a
   classification/severity when there is genuine provider data to base it
   on. A failed or unconfigured provider never becomes "Safe."

## How log analysis works

`log_parser.parse_log()` accepts `.txt`, `.log`, `.csv`, and `.json`
content, decodes it (with a `latin-1` fallback if it isn't valid UTF-8),
and applies a small, explicit set of regex patterns per line/record:
brute force, port scan, privilege escalation, and malware indicators. Each
match becomes a `LogFinding` with a severity, extracted IPv4s, and a
timestamp if one is present. A file that can't be parsed at all (e.g.
invalid JSON) returns `parse_ok=False` with a specific message rather than
silently reporting zero findings.

## How file analysis works

`malware_scan.analyze_file()` always computes SHA-256/MD5 and reports file
size and a suspicious-extension check. If YARA is available, the file is
scanned against `rules/malware_rules.yar`. If a VirusTotal key is
configured, the SHA-256 is looked up against VirusTotal's file-reputation
endpoint. The final status (`MALICIOUS INDICATORS` / `SUSPICIOUS` /
`LOW RISK / NO LOCAL INDICATORS` / `UNKNOWN` / `ANALYSIS FAILED`) reflects
exactly what was actually checked — `UNKNOWN` is returned rather than a
false "Safe" when no local indicator fired and no VirusTotal key is
configured.

## MITRE ATT&CK integration status

`mitre_mapper.py` maps a small, explicit set of log-finding categories and
"Malicious" IOC classifications to MITRE ATT&CK techniques, each with a
one-line rationale for the relationship. "Suspicious" (mid-confidence)
IOC verdicts are deliberately **not** mapped — that signal isn't strong
enough to defensibly attribute a specific technique. The MITRE ATT&CK page
in the app shows the full reference table of every mapping currently
defined.

## ML component status: **not integrated, by design**

`train_model.py` (standalone, not imported by `app.py`) trains a
`RandomForestClassifier` on the CIC-IDS2017 "Friday Afternoon DDoS"
dataset. The resulting `models/model.pkl` expects **78 CICFlowMeter
network-flow features** (e.g. `Flow IAT Std`, `Fwd Packets/s`,
`Bwd Header Length`) extracted from raw packet captures.

Nothing in ThreatScope's actual inputs — a single IOC string, a text/CSV
/JSON log file, or an uploaded file for hashing — can be converted into
those 78 flow-level features without a separate pcap-to-flow pipeline
(e.g. CICFlowMeter) that does not exist in this repository. Feeding the
model anything else would produce a meaningless prediction, which would be
worse than not having the feature. `models/model.pkl` and `train_model.py`
are kept in the repo as a documented, reproducible artifact of prior work,
not as a live app feature. The Settings page states this plainly.

If you want to genuinely integrate it in the future, you would need to
add a pcap/flow feature-extraction step to the file-analysis pipeline —
that is out of scope for this audit/repair pass.

## YARA status

Genuinely functional: `yara-python` is a real runtime dependency,
`rules/malware_rules.yar` is compiled once at first use, and matches are
shown in File Analysis results. If `yara-python` isn't installed or the
rules file is missing, the Settings page and File Analysis both report
this plainly (`YARA_NOT_INSTALLED` / `RULES_FILE_MISSING`) rather than
silently doing nothing.

---

## UI notes

The interface is a native Streamlit **dark theme** (`.streamlit/config.toml`),
matched exactly to ThreatScope's existing color palette, plus a thin CSS
layer in `app.py` for the masthead, metric cards, severity/status pills,
and the compact Recent Investigations row list. `.streamlit/config.toml`
is picked up automatically by Streamlit Cloud — no extra deployment step
is needed for it.

**Sidebar toggle fix:** an earlier CSS revision included a blanket
`header{ visibility:hidden; }` rule intended to hide Streamlit's default
toolbar. That rule also hid `[data-testid="stExpandSidebarButton"]` —
the control Streamlit renders inside the header to re-open a collapsed
sidebar — which meant a user who collapsed the sidebar had no way to get
it back. The current CSS instead targets only the specific decorative
elements (`#MainMenu`, `[data-testid="stAppDeployButton"]`) and explicitly
forces the expand/collapse controls to stay visible, so the sidebar can
always be reopened. `tests/test_ui_refinement.py` has a regression test
for this.

---

## Limitations

- **Single, unauthenticated app** — anyone with the URL can use it; there
  is no login/access control.
- **IOC detection is format-based**, not exhaustive (e.g. no IPv6 support
  yet).
- **VirusTotal's public API has strict rate limits** (typically 4
  requests/minute on a free key) — expect `RATE_LIMITED` under moderate
  use.
- **The ML component is not wired into any live feature** — see above.
- **YARA rules are minimal** (one illustrative rule) — this is a
  demonstration of a working pipeline, not a production ruleset.
- **SQLite persistence is local to the deployment instance** — on
  Streamlit Community Cloud specifically, the filesystem is not
  guaranteed to persist across redeploys/restarts; treat history as
  durable within a running instance, not permanently archived.

## Security notes

- No credential is ever hardcoded in source. All three provider keys are
  loaded exclusively through `config.py`, from Streamlit secrets or
  environment variables.
- `.env` is git-ignored; only `.env.example` (placeholders) is committed.
- **The repository's git history contains an earlier commit with real,
  now-rotated API keys.** Removing a file from the latest commit does not
  remove it from history — those old keys must be treated as permanently
  compromised (they already were, and have been rotated). If you want the
  old blobs gone entirely, that requires a history rewrite
  (`git filter-repo` or BFG Repo-Cleaner) followed by a force-push, or
  simply starting this repository fresh from the current tree. This
  README does not attempt that for you.
- Every outbound HTTP call has an explicit timeout and explicit
  error-status handling — no call can hang the app indefinitely, and no
  provider failure crashes the Streamlit process.

---

## How to run locally

See "Local installation" above. In short:
```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in your keys
streamlit run app.py
```

## Deployment (Streamlit Community Cloud)

1. Push this repository to GitHub (with `.env` excluded — confirm it's
   not tracked: `git ls-files | grep .env` should show only
   `.env.example`).
2. On [share.streamlit.io](https://share.streamlit.io), create a new app
   pointing at this repo, branch `main`, main file `app.py`.
3. In the app's **Settings → Secrets**, paste the TOML block from
   "Streamlit Cloud Secrets setup" above with your real key values.
4. Deploy. `requirements.txt` will be installed automatically.

## Running the test suite

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

This includes unit tests for IOC detection/validation, HTTP error
handling, log parsing, file analysis, YARA, and SQLite persistence, plus
Streamlit `AppTest` end-to-end tests that drive the actual app (missing
keys, invalid input, simulated total provider outage) and assert it never
raises.
