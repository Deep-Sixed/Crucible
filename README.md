# Crucible

**Multi-agent coding evaluation & boundary-attestation engine for EVECOR.**

Crucible referees competing coding agents attempting the same task against a
frozen Git baseline, then returns a scored, boundary-audited verdict for
operator approval. A crucible is the vessel where you test something's worth
*and* burn off its impurities — that is exactly what this component does in one
pass: it scores each attempt's quality **and** flags every boundary violation
(secrets touched, out-of-scope edits, unauthorized pushes).

It is entirely local. No network, no database, no external services, and — by
construction — **no ability to send email, mutate a mailbox or CRM, submit a
browser form, write secrets, or commit/merge/push Git.** Its report is
trustworthy because the engine producing it cannot perform the side effects it
attests to.

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
| **closeout** | Writes the terminal `HarnessCloseout`: models observed, artifact paths, validation summary, your explicit `operator_decision`, and the HITL side-effect attestations — all of which are `false` because the engine cannot perform them. Marks the run `closed`. |

---

## The boundary model (the point of Crucible)

Every result and every response carries the **`NO_SIDE_EFFECTS`** attestation
block — a set of flags that are structurally always `false`:

```
outbound_email_sent            mailbox_mutated
application_status_mutated     browser_submit_executed
secrets_written                database_mutated
git_commit_performed           git_merge_performed
git_push_performed
```

They are not runtime-computed guesses — the code paths to do these things do not
exist in Crucible. The attestation is a *guarantee by construction*.

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
`SCHEMA_VERSION = 2`; every record carries its own `schema_version`.

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
schema_version` (+ the `NO_SIDE_EFFECTS` attestation block on serialization)

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

Test/build commands are parsed with `shlex` and executed **without shell
expansion** (`shell=False`), so a task command cannot inject shell operators.

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
pytest                                            # 7 tests
crucible --help
```

Verified on this box under Python **3.14.5**: editable install, `import crucible`,
7/7 tests, CLI (`crucible` and `python -m crucible`), and a full
`create → register → collect → compare → closeout` run against the live EVECOR
repo (recommended `claude`, `operator_approval_required = true`, all boundary
attestations `false`).

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
- **No side effects.** The engine cannot email, mutate a mailbox/CRM/DB, submit a
  browser form, write secrets, or commit/merge/push. The attestations are true by
  construction, not by check.
- **Operator-gated.** No attempt is ever auto-accepted; `operator_decision` is
  explicit and required.
- **Tamper-evident inputs.** Sensitive paths are fingerprinted; artifacts are
  written atomically under a per-run lock.
