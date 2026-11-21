# Crucible

**Multi-agent coding evaluation & boundary-attestation engine for EVECOR.**

Crucible referees competing coding agents attempting the same task against a
frozen Git baseline, then returns a scored, boundary-audited verdict for
operator approval. A crucible is the vessel where you test something's worth
*and* burn off its impurities — that is exactly what this component does in one
pass: it scores each attempt's quality **and** flags every boundary violation
(secrets touched, out-of-scope edits, unauthorized pushes).

It is entirely local: no network, database, or external services. Agent-controlled
test and build commands run in a Bubblewrap sandbox on a disposable copy of the
attempt. If that isolation cannot be established, Crucible refuses to run them.

---

## Table of contents

1. [Why it exists](#why-it-exists)
2. [The lifecycle](#the-lifecycle)
3. [The boundary model](#the-boundary-model-the-point-of-crucible)
4. [Data model](#data-model)
5. [On-disk artifacts](#on-disk-artifacts)
6. [CLI reference](#cli-reference)
7. [Python API](#python-api)
8. [Scoring](#scoring)
9. [Install, test, verify](#install-test-verify)
10. [History & naming](#history--naming)
11. [Backward compatibility](#backward-compatibility)
12. [Design guarantees](#design-guarantees)

---

## Why it exists

Given N coding agents (Claude, Codex, Cursor, Composer, Gemini, …) that each
attempt the *same* change, two questions matter:

1. **Which one did it best?** — a scored, multi-dimensional comparison.
2. **Which ones can you prove stayed in bounds?** — did any write a secret, edit
   outside its lane, or try to push to a protected branch?

Crucible answers both from a single evidence trail, and forces an explicit
human decision before anything is treated as accepted. It is the tool that lets
you pit agents against each other on a real EVECOR change and get an auditable
result — without any agent being able to touch the vault, email, or `main`.

Crucible does **not** run the agents. You (or your orchestration) run them in
worktrees; Crucible pins the baseline, ingests what each produced, judges it,
and records the verdict.

---

## The lifecycle

```
create ──▶ register(×N) ──▶ collect ──▶ compare ──▶ closeout
  │            │               │           │            │
baseline    one per         diff +      score +     terminal record
 commit      agent         boundary    recommend   + HITL attestations
                            + tests    + blockers   + operator decision
```

| Stage | What it does |
|---|---|
| **create** | Pins a run to a Git baseline commit and writes a manifest: task summary, workspace, optional `allowed`/`prohibited` path lists, and required test/build commands. This is the "before any agent touched it" snapshot. |
| **register** | Records that an agent took a turn in a given worktree. One `ModelAttempt` per agent per run. |
| **collect** | For each attempt: diffs the worktree against the baseline (tracked **and** untracked files), runs the required tests/builds, and evaluates the diff against the run's boundaries. Produces one `AttemptResult` per attempt. |
| **compare** | Scores every attempt across multiple dimensions, recommends the best, and lists blockers. A boundary violation becomes a **blocker**, not merely a lower score. Always sets `operator_approval_required = true`. |
| **closeout** | Writes the terminal `HarnessCloseout`: models observed, artifact paths, validation summary, your explicit `operator_decision`, and the evidence-based side-effect attestations. Marks the run `closed`. |

---

## The boundary model (the point of Crucible)

Every response carries an `attestations` block. Each side effect has one of three
states, and Crucible never reports that something did not happen unless it can
establish that:

| Status | Meaning |
|---|---|
| `verified_absent` | Validation ran isolated and the repository was unchanged. |
| `observed` | Crucible saw the side effect. This blocks a recommendation. |
| `unverified` | Crucible cannot establish either way. This also blocks a recommendation. |

The covered keys are:

```
outbound_email_sent            mailbox_mutated
application_status_mutated     browser_submit_executed
secrets_written                database_mutated
git_commit_performed           git_merge_performed
git_push_performed
```

**Scope limit:** attestations cover Crucible's validation commands only
(`attestation_scope: validation_commands`). Crucible does not watch the agent's own
session, so `agent_session_covered` is always `false`. Run agents in their own
sandbox if you need evidence about what they did before collection.

**Isolation:** each command gets a fresh copy of tracked and untracked files, minus
sensitive paths, with no network, no host home, no inherited credentials, no
capabilities, and `no_new_privs`, so `sudo` cannot elevate. A preflight proves these
properties before any command runs. Git reads also run read-only in the sandbox,
because repository config and filters can execute code. Crucible fingerprints HEAD,
refs, status, and file contents before and after validation; any change is a blocker.

Bubblewrap is required when a run has test or build commands. Extra read-only
toolchains, such as a virtualenv, can be exposed with the colon-separated
`CRUCIBLE_SANDBOX_RO_PATHS`. CPU, memory, and process counts are not yet limited.

Separately, each attempt's diff is checked against three path classes:

- **Scope** — files outside the run's `allowed_paths` (if any were declared).
- **Prohibited** — files inside the run's `prohibited_paths`.
- **Sensitive** — anything matching `SENSITIVE_PATH_PATTERNS` (`.env`, `.kdbx`,
  `keepass`, private keys, credentials, …). Sensitive hits are stored as
  **SHA-256 fingerprints**, never as literal paths, so the artifact itself
  cannot leak the location of a secret.

Any hit in these classes zeroes the attempt's safety score and surfaces as a
comparison blocker requiring operator review.

---

## Data model

All records are dataclasses in `crucible.schemas`, serialized to JSON. Current
`SCHEMA_VERSION = 3`; every record carries its own `schema_version`.

**`HarnessRun`** — the run manifest
`run_id · workspace · task_summary · repo_root · baseline_commit · baseline_ref ·
allowed_paths · prohibited_paths · required_tests · required_builds · status ·
created_at · updated_at · schema_version`

**`ModelAttempt`** — one agent's turn
`attempt_id · run_id · model_provider · model_name · ide_host · worktree_path ·
baseline_commit · registered_at · schema_version`

**`AttemptResult`** — what an attempt produced
`attempt_id · run_id · model_provider · model_name · files_changed ·
lines_added · lines_deleted · untracked_files · scope_violations ·
prohibited_violations · sensitive_paths_found · test_results · build_results ·
tests_passed · tests_total · builds_passed · builds_total · build_passed ·
collection_errors · collected_at · schema_version`

**`ComparisonResult`** — the verdict
`run_id · comparison_id · attempt_ids · recommended_attempt_id ·
recommended_provider · scores · blockers · operator_approval_required ·
generated_at · schema_version`

**`HarnessCloseout`** — the terminal record
`entity_type · run_id · workspace · baseline_commit · task_summary ·
models_observed · artifacts · validation · operator_decision · closed_at ·
schema_version` (+ the evidence-based `attestations` block)

Providers: `cursor · codex · claude · composer · gemini · local · other`.
Run status: `active · completed · closed`.
Operator decision: `pending_review · approved · …`.

---

## On-disk artifacts

Everything lives under a runs root (default: `<component>/var/runs/`, overridable
with `--runs-root`). Writes are **atomic** (`tempfile` + `os.replace`) and
serialized by a **per-run advisory lock** (`fcntl.flock` on `<run>/.lock`).

```
var/runs/
└── crucible-run-YYYYMMDD-xxxxxxxx/
    ├── .lock
    ├── manifest.json                      # HarnessRun
    ├── baseline.json                      # resolved baseline commit
    ├── attempts/
    │   ├── <attempt_id>.json              # ModelAttempt
    │   └── <attempt_id>_result.json       # AttemptResult
    ├── comparisons/
    │   └── <comparison_id>.json           # ComparisonResult
    └── closeout.json                      # HarnessCloseout
```

`var/runs/` is git-ignored — it is runtime state, not source.

---

## CLI reference

Console script `crucible` (also `python -m crucible`). Global option:
`--runs-root PATH`. Every command prints a JSON result to stdout.

```sh
crucible create   --repo PATH --baseline REF --task "..." [--workspace evecor]
                  [--run-id ID] [--allow PATH ...] [--prohibit PATH ...]
                  [--test 'cmd' ...] [--build 'cmd' ...] [--dry-run]
crucible register RUN_ID --provider claude --model fable-5 --host cli --worktree PATH
                  [--attempt-id ID]
crucible collect  RUN_ID
crucible compare  RUN_ID [--attempt ATTEMPT_ID ...]
crucible closeout RUN_ID [--decision approved] [--dry-run]
crucible status   [RUN_ID]
```

Test/build commands are parsed with `shlex`, executed without shell expansion, and
always run inside the sandbox.

---

## Python API

```python
import crucible as c

run = c.create_harness_run(
    task_summary="add feature", baseline_ref="HEAD",
    repo_root="/path/to/repo", workspace="evecor",
    allowed_paths=["src/"], prohibited_paths=["infra/"],
    required_tests=[["pytest", "-q"]], runs_root=None,
)
c.register_model_attempt(run_id=run["run_id"], model_provider="claude",
                         model_name="fable-5", ide_host="cli", worktree_path="/path/to/wt")
c.collect_run_results(run_id=run["run_id"])
c.compare_model_results(run_id=run["run_id"])
c.record_harness_closeout(run_id=run["run_id"], operator_decision="approved")
c.get_harness_status()
```

Public surface: `create_harness_run · register_model_attempt ·
collect_run_results · compare_model_results · get_latest_comparison ·
record_harness_closeout · get_harness_status`, the submodules
`schemas · run_manager · evaluation_engine · comparison_engine · closeout ·
artifact_store`, and the typed errors `RunManagerError · EvaluationEngineError ·
ComparisonEngineError · CloseoutError`.

Every function accepts `runs_root=` for isolation and several accept
`dry_run=True`, which returns the planned response shape and writes nothing.

---

## Scoring

`compare_model_results` scores each attempt across independent dimensions and an
`overall` roll-up:

`correctness · build · scope_control · safety_boundaries · maintainability ·
collection_integrity → overall`

Scoring is deterministic (same inputs → same scores). A boundary violation zeroes
`safety_boundaries`/`scope_control` and registers a blocker;
`operator_approval_required` is always `true`, so a high score never auto-accepts
an attempt.

---

## Install, test, verify

```sh
cd /path/to/Crucible
python -m venv .venv && . .venv/bin/activate     # Python 3.11+ (3.14.x target)
pip install -e .
pytest                                            # requires bubblewrap
crucible --help
```

CI runs lint and the full suite on Ubuntu with Bubblewrap under Python 3.14.

---

## History & naming

Crucible was previously the source-lost `ai_harness`: only `.pyc` bytecode
remained (Python 3.14, undecompilable). The contract was recovered by bytecode
introspection, verified against the surviving run artifacts, and rebuilt as
clean source with the Nexus/Datacore coupling removed (the old `datacore_bridge`
was already a local-only no-op, so nothing was lost). Renamed `ai_harness →
Crucible` on 2026-07-18 because "harness" named the plumbing, not the job.

The original bytecode, the old run artifacts, and an alternate reconstruction are
preserved, unchanged, under:

```
/path/to/previous-harness-archive/
```

That archive records the component's former identity and must not be renamed or
rewritten.

---

## Backward compatibility

- **Run IDs**: new runs use the `crucible-run-*` prefix. Legacy `harness-run-*`
  directories remain fully listable and loadable — no validator enforces a prefix.
- **`entity_type`**: new closeouts write `crucible_run`; readers accept the
  legacy `ai_harness_run` value. It is a label, not control flow.
- **Schema**: `schema_version` is stamped on every record so future migrations
  can branch on it. v1 artifacts read under the current dataclasses.
- No permanent `ai_harness` compatibility shim is installed — nothing imports the
  old package. Add one only if a real consumer turns up.

---

## Design guarantees

- **Local-only.** Filesystem is the sole store. No DB, no network, no Datacore.
- **Evidence-based attestations.** A side effect is reported absent only when
  isolation and before/after repository checks support it; otherwise it is
  `observed` or `unverified` and blocks a recommendation.
- **Fail closed.** Without a working sandbox, validation commands do not run.
- **Operator-gated.** No attempt is ever auto-accepted; `operator_decision` is
  explicit and required.
- **Tamper-evident inputs.** Sensitive paths are fingerprinted; artifacts are
  written atomically under a per-run lock.
