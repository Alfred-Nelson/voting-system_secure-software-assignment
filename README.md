# Secure E-Voting Prototype: Senate Voting Subsystem

This is a functional prototype of the voting subsystem for the Electronic Voting Platform in the group assignment.

> All people, parties, candidates and data are fictional. This is a university prototype and is **not** for real elections.

## Contents

1. [Requirements](#requirements)
2. [Setup](#setup)
3. [Running the system](#running-the-system)
4. [Demo walkthrough](#demo-walkthrough)
5. [Demo accounts](#demo-accounts)
6. [Resetting the demo](#resetting-the-demo)
7. [Verifying results independently](#verifying-results-independently)
8. [Other tools](#other-tools)
9. [Configuration](#configuration)
10. [Tests and security checks](#tests-and-security-checks)
11. [Troubleshooting](#troubleshooting)

## Requirements

- Python 3.12 or newer (CI uses 3.12; it also runs on 3.13/3.14)
- `git` and a modern browser (WebCrypto is needed for voting)
- No database server is needed: the system uses SQLite files created automatically

## Setup

The `data/` and `certs/` folders hold keys, passwords and TOTP secrets, so they are **git-ignored**.
They are not in the repository. Every developer generates their own copy with the commands below.

```bash
# 1. Get the code
git clone https://github.com/Alfred-Nelson/voting-system_secure-software-assignment.git
cd voting-system_secure-software-assignment

# 2. Create a virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate         # Windows: venv\Scripts\activate
pip install -r requirements.txt  # use requirements-dev.txt if you also want to run tests

# 3. Create a self-signed TLS certificate (writes certs/server.crt and certs/server.key, valid 90 days)
python tools/gen_cert.py

# 4. Create the demo election (writes data/ and prints the demo logins)
python tools/setup_demo.py
```

What each step creates:

| Command | Creates | Contents |
|---|---|---|
| `python tools/gen_cert.py` | `certs/` | Self-signed certificate and key for HTTPS. Only needed for `--tls`. Re-run it when it expires. |
| `python tools/setup_demo.py` | `data/` | The identity, ballot and audit databases, the encrypted keystore, a development master key (`DEV_ONLY_master.key`), and `demo_credentials.json` (demo passwords, TOTP secrets and the results API key). |

## Running the system

Start the server from the project root, in your own terminal so `Ctrl+C` stops it:

```bash
python run.py --tls      # https://127.0.0.1:3775   TLS 1.3 only (recommended)
python run.py            # http://127.0.0.1:3776    plain HTTP, development only
python run.py --port 8080 --host 127.0.0.1   # custom port or host
```

With `--tls` your browser will warn about the self-signed certificate. Choose *Advanced* and then *Proceed*.

| Page | URL path | Used by |
|---|---|---|
| Voter | `/` | Voters: sign in, fill in the ballot paper, cast and get a receipt |
| Bulletin board | `/board` | Anyone: check a receipt code and see all recorded receipts |
| Staff console | `/admin` | Staff: election control, keys, alerts, candidates, approvals, audit, backups |
| Health check | `/health` | Monitoring |

The election starts in `setup` status. **Voting is not possible until an administrator opens the polls.**

## Demo walkthrough

1. **Open the polls.** Go to `/admin`, sign in as `admin1`, and on the Election tab click *Open polls*.
2. **Vote.** Go to `/`, sign in as a voter such as `NSW1000001`, number the ballot above or below the line, and click *Cast*. Copy the receipt code.
3. **Check the receipt.** Open `/board` and paste the receipt code.
4. **Re-vote (optional).** A voter may vote again while polls are open. Only the latest online vote counts.
5. **Close the polls and count.** In `/admin` as `admin1`, click *Close polls* and then *Verify ledger & run count*. The elected candidates are shown by name and party.
6. **Staff features to try:**
   - `auditor1`: verify the audit hash chain and the ballot ledger.
   - `officer1`: mark a voter as having voted at a polling station or by post.
   - `delegate_nsw1` and `delegate_nsw2`: edit candidate details (before voting opens) and approve an exclusion or recount. Two different delegates must approve (dual authorisation).
   - `admin1`: view and rotate keys, create an encrypted backup.

The demo election is a fictional NSW Senate contest with 2 vacancies, 3 party groups (A, B, C with two candidates each) and 1 ungrouped independent.

## Demo accounts

`setup_demo.py` prints all of these when it finishes. They are also saved in `data/demo_credentials.json`.

| Account | Role | Notes |
|---|---|---|
| `NSW1000001` to `NSW1000008` | Voter | Eligible NSW voters |
| `NSW1000009`, `NSW1000010`, `VIC2000001` | Voter | Deliberately ineligible (under age, not enrolled, other state) |
| `admin1` | Administrator | Opens and closes polls, runs the count, keys, backups |
| `officer1` | Employee | Marks offline votes, views terminals and alerts |
| `delegate_nsw1`, `delegate_nsw2` | Commissioner's delegate (NSW) | Candidate edits and approvals for NSW |
| `delegate_vic1` | Commissioner's delegate (VIC) | Used to show that approvals outside your state are refused |
| `auditor1` | Auditor | Read-only audit and ledger verification |

- Voter password: `Voter#Pass2026`. Staff password: `Staff#Pass2026` (demo values, can be overridden with `EVOTE_DEMO_VOTER_PASSWORD` and `EVOTE_DEMO_STAFF_PASSWORD` before running `setup_demo.py`).
- Every sign-in also needs a six-digit one-time code (MFA). It stands in for an authenticator app:

```bash
python tools/totp_code.py NSW1000001      # a voter
python tools/totp_code.py admin1          # a staff account
python tools/totp_code.py admin1 --uri    # otpauth:// link to add to a real authenticator app
```

Codes change every 30 seconds. Each code can only be used once, so wait for the next one if a sign-in is rejected.

## Resetting the demo

To start again with a clean election (new keys, no votes, all voters able to vote):

```bash
# 1. Stop the server first (Ctrl+C in its terminal)
python tools/setup_demo.py
python run.py --tls
# 2. Hard-refresh the browser (Cmd+Shift+R / Ctrl+Shift+R)
# 3. Open the polls again as admin1
```

**Always stop the server before resetting.** A running server keeps the old keys in memory, which causes
"credential was not issued by the AEC" or "invalid blind signature" errors. To check nothing is still running:

```bash
lsof -iTCP -sTCP:LISTEN -n -P | grep -i python
```

A voter who is issued a credential cannot be issued another one, by design (it prevents double voting and the
credential cannot be linked back to the voter). If a voting attempt fails after the credential was issued,
reset the demo.

## Verifying results independently

After the count, anyone with a registered API key (printed by `setup_demo.py`) can check the signed results:

```bash
python tools/verify_results.py https://127.0.0.1:5443 <API_KEY> --insecure
python tools/verify_results.py https://127.0.0.1:5443 <API_KEY> --insecure --rounds   # also print every count round
```

`--insecure` is only needed because of the self-signed certificate. The tool verifies the Ed25519 signature,
then prints the elected candidates as `Name (Party)`, the number of formal and informal ballots, the quota and
the input digest. The signed result contains a `candidates` lookup (ID to name and party), so names cannot be
altered without breaking the signature.

Terms used in the output:
- **Formal / informal:** valid ballots that are counted, and invalid ballots that are not.
- **Quota:** the votes needed to be elected outright: `floor(formal / (vacancies + 1)) + 1` (Droop quota).
- A candidate can still be elected without reaching the quota when the number of candidates left equals the seats left.

## Other tools

| Command | Purpose |
|---|---|
| `python tools/simulate_terminal.py PS-SYD-001 http://127.0.0.1:5000` | Simulates a polling terminal sending heartbeats; stop it with `Ctrl+C` and the console raises an offline alert after 60 seconds |
| `python tools/backup_restore.py backup` | Creates an encrypted backup of the data |
| `python tools/backup_restore.py restore <backup file> <target folder>` | Restores a backup into a new folder |
| `python tools/sign_release.py` | Signs the release manifest; with `EVOTE_REQUIRE_SIGNED_BUILD=1` the server refuses to start if the code was changed |

## Configuration

Election and security settings are in [app/config.py](app/config.py). Common ones:

| Setting | Default | Meaning |
|---|---|---|
| `VACANCIES` | `2` | Seats to fill (a real half-Senate election has 6) |
| `ELECTION_STATE` | `NSW` | State the ballot paper is for |
| `PRIVILEGED_IDLE_TIMEOUT_SEC` | `180` | Staff session timeout |
| `VOTER_IDLE_TIMEOUT_SEC` | `600` | Voter session timeout |
| `MAX_FAILED_LOGINS` / `LOCKOUT_MINUTES` | `5` / `15` | Account lockout |

Environment variables:

| Variable | Meaning |
|---|---|
| `EVOTE_DATA_DIR` | Use a different data folder (handy for a second, separate demo instance) |
| `EVOTE_MASTER_KEY` | 64-hex-character master key; if unset a development key is created in `data/` |
| `EVOTE_MISSION_NETWORKS` | Allowed networks for overseas mission terminals |
| `EVOTE_REQUIRE_SIGNED_BUILD` | `1` makes the server refuse to start if the code differs from the signed manifest |
| `EVOTE_DEMO_VOTER_PASSWORD`, `EVOTE_DEMO_STAFF_PASSWORD` | Demo passwords used by `setup_demo.py` |

Restart the server after changing `config.py`. To count a different number of seats, change `VACANCIES` and run
`setup_demo.py` again.

## Tests and security checks

```bash
pip install -r requirements-dev.txt
pytest                                           # full test suite
pytest --cov=app --cov=client --cov-report=term-missing
bandit -r app client tools -ll                   # static security scan
pip-audit -r requirements.txt                    # dependency vulnerabilities
```

The tests use their own temporary data, so they do not touch your `data/` folder. CI
([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the tests, bandit, pip-audit and an SBOM build.

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| `No certificate found - run: python tools/gen_cert.py` | `certs/` is missing. Run `python tools/gen_cert.py`, or start without `--tls` |
| "Voting is not open yet" | Polls are still in `setup`. Sign in as `admin1` and click *Open polls* |
| "credential was not issued by the AEC" or "AEC returned an invalid blind signature" | The server or browser tab has old keys after a reset. Stop all servers, run `setup_demo.py`, start the server, hard-refresh the browser |
| "already voted (online)" with no receipt | A credential was issued but the vote failed. Reset the demo (see above) |
| One-time code rejected | Codes are single-use and last 30 seconds. Wait for a new one. Check your computer clock |
| Account locked | Five failed sign-ins lock an account for 15 minutes. Reset the demo to clear it |
| Port already in use | Another server is still running. Find it with the `lsof` command above and stop it, or use `--port` |
| Browser certificate warning | Expected with the self-signed certificate. Choose *Advanced* and then *Proceed* |
