# Contributing

## Commit convention

Commits use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <imperative summary>
```

Types in use in this repo: `feat`, `fix`, `docs`, `chore`, `ci`, `test`. The existing
history is the reference — match its shape rather than inventing a new one.

## One commit per logical unit, **per file** — the hard rule

Every commit **and every push** must touch **exactly one file**. Not "on average" —
exactly one, every time.

- Never bundle a source change with its test, and never bundle a doc update with the
  code it describes, even when they are logically one unit of work.
- If a logical change genuinely requires edits to several files, that is several
  sequential commits — **one file each** — pushed in order. Do not squash them
  together afterwards.
- This is stricter than the earlier "one commit per logical unit" rule. It is now
  one commit per logical unit **per file**.
- It applies to every repository in this org: `stellar-agent-guard-sdk`,
  `stellar-agent-guard-contracts`, and `stellar-agent-guard-dashboard`.

Why: each commit stays independently reviewable and revertable, and a code change can
never hide inside a `docs:` commit or vice versa.

Check before you commit — either of these must print exactly one path:

```bash
git diff --cached --name-only
git show --stat HEAD
```

## Branch protection and CI

`main` is protected by the `main-protection` ruleset:

- the required status check is named exactly **`ci`**;
- **one approving review** is required, stale reviews are dismissed on push, and
  GitHub does not permit self-approval;
- allowed merge methods are `merge`, `squash` and `rebase`.

**Solo-maintainer bypass policy.** As a solo-maintained repository, PRs require a green `ci` check but no second-party review; the maintainer's named-actor bypass on `main-protection` is used deliberately for merges, and that is documented here as standard procedure — not an emergency exception. Ordinary PRs still go through the full `ci` required-check gate; the bypass only removes the structurally-unsatisfiable second-reviewer requirement. If a second maintainer joins in future, they should be added as a required reviewer and this section revisited.

Do not modify the ruleset to work around a required check that is legitimately blocked.

CI reports **one required check**, plus a scheduled workflow that is deliberately not
part of it:

- **`ci`** — required, and the only check that gates a merge. Runs typecheck, lint, the
  unit tests, and the **enforcement-path evidence gate**. It touches no secret, so
  nothing in it can silently mask a skip: every step either really runs or the job
  fails.
- **`live-suite`** (`.github/workflows/live-suite.yml`) — **never run on a pull
  request**. Runs the live testnet suite weekly (`schedule`) and on demand
  (`workflow_dispatch`) to catch host/testnet drift. `PHASE2_ENV_FILE` is referenced
  only in that workflow, and it has no `pull_request` / `pull_request_target` trigger,
  so a pull request — including a forked one — can never reach the secret.

### The live testnet suite is not run on every PR

It is:

1. **required locally before any PR that touches the enforcement path** — `src/tx.ts`,
   `src/invoke.ts`, `src/policy.ts`, `src/preflight.ts`. Run `npm run test:integration`,
   then commit the fresh output to `tests/fixtures/integration-evidence.md` **in the same
   PR**. The required `ci` job checks that the evidence file was touched; it cannot
   verify the numbers (that needs the network), only that fresh evidence was supplied.
   A PR that changes the path without it **fails `ci`**.
2. **run automatically on a schedule**, so a protocol or RPC change is caught even when
   nobody is editing the code.

A green `ci` therefore means "the required checks ran", not "the live suite ran on this
change". The committed evidence file is the record for the change itself.

## Branch lifecycle

- All work happens on a feature branch and lands through a pull request. **Never push to
  `main` directly** — not before this rule, and not after it.
- After a PR merges, and **only** then:
  1. confirm the merge actually landed — `git log main` shows the merge/squash/rebase
     commit and the PR reports a populated `mergedAt`;
  2. delete the remote branch (`git push origin --delete <branch>`, or the "Delete branch"
     button GitHub shows on a merged PR);
  3. delete the local branch with `-d`, **not** `-D`. If `-d` refuses, that is a signal the
     merge did not land the way you think — stop and check rather than forcing it.
- Sweep for stray branches (`git branch -a`, `gh api repos/{owner}/{repo}/branches`) and
  delete the ones already merged into `main`. **Never delete an unmerged branch** to hit a
  `main`-only target — that silently discards unmerged work.
- Verify with `git branch -a`: it should show `main` and nothing else.
- The same rule applies to `stellar-agent-guard-contracts` and
  `stellar-agent-guard-dashboard`.

## Issues and labels

The tracked backlog uses one label taxonomy, applied identically in every repo in this org.
It is defined and applied by `scripts/create-issue-backlog.sh`, which is idempotent — safe to
re-run, and reports a repo it cannot write to rather than aborting the run:

| Label | Meaning |
| --- | --- |
| `tier:blocker` | blocks a phase exit; not fixable by an agent alone |
| `tier:maintainer-decision` | a human call is required; do not guess |
| `tier:enhancement` | non-blocking; revisit when its trigger is met |
| `scope:sdk` / `scope:contracts` / `scope:dashboard` | which repo's code/config the issue concerns, so the backlog can be filtered across repos in one query |

An issue carries at least one `tier:` label and exactly one `scope:` label.

Wave complexity (**Trivial / Medium / High**) is deliberately **not** a label here: the Drips
Wave docs assign it when an issue is added to a Wave Program in the dashboard, and the Wave
bot applies its own program label. Keeping the tier taxonomy orthogonal to it means neither
scheme has to be renamed later.

Anything still open when a phase closes gets an issue, not just a note in a pull request or a
chat log.

## Local gates before pushing

```bash
npm run typecheck
npm run lint
npm test
npm run build && npm run test:exports   # packs the tarball and resolves every export
npm run test:integration   # live testnet; needs .env.phase2 (template: .env.phase2.example)
```

## Cross-editor standardization

Contributors use diverse operating systems and editors. To prevent cross-platform formatting churn:

- `.editorconfig` establishes baseline editor formatting: 2-space indentation, UTF-8 character encoding, LF line endings, and trimmed trailing whitespace. Note the hierarchy: the project formatter/linter is authoritative; `.editorconfig` assists editors only.
- `.gitattributes` normalizes text line endings to LF on checkout and commit (`* text=auto eol=lf`), preventing Windows CRLF churn.

## Test tiers and fixtures

- **Unit** (`npm test`) — no network, no secrets, deterministic.
- **Live** (`npm run test:integration`) — real testnet; needs `.env.phase2`
  (template: `.env.phase2.example`). Not run on pull requests; see
  "The live testnet suite is not run on every PR" above.

Both tiers run through one runner configuration, `tests/test.config.ts`, read by
`scripts/run-tests.ts`. Projects are named and explicit:

| Script | Project(s) | Notes |
| --- | --- | --- |
| `npm test` / `npm run test:unit` | `unit` (`tests/unit`) | Offline; Node test-runner default concurrency. |
| `npm run test:watch` | `unit` (`tests/unit`) | Development loop: Node's test-runner watch mode, re-running the unit suite on every change to a watched file, so you can edit → read the failure → fix → repeat without re-issuing `npm test`. Same project, same `tsx` transform, same files as `npm test`. |
| `npm run test:integration` | `integration` (`tests/integration`) | Live; concurrency pinned to `1`, because the files share on-chain state. Validates `.env.phase2` up front on entry, failing fast with a single actionable message before launching test files if missing or incomplete. |
| `npm run test:all` | every project, one run | Both suites in a single invocation. |
| `npm run test:coverage` | every project, one run, coverage | Node's `--experimental-test-coverage`; needs `.env.phase2`, because the integration project is included. |

Both projects share the `tsx` transform, so the same `src/` modules load
identically in either tier. A project's invariants — its directory has matching
files, the live project stays serialised — are asserted by
`tests/unit/test-runner.test.ts` rather than left to convention.

When `.env.phase2` is absent or incomplete, the test runner fails immediately at entry with a single actionable message pointing to `.env.phase2.example` and the provision command (`npm run deploy:phase2`) without cascading test cancellations:

```
.env.phase2 was not found in the working directory.

Copy the documented template and fill it in:  cp .env.phase2.example .env.phase2
Or provision a fresh instance (writes the file, including PHASE2_ISSUER_SECRET):  npm run deploy:phase2
```

An existing-but-incomplete file lists all missing required keys in one place:

```
.env.phase2 is incomplete: 6 required key(s) are missing:
  - PHASE2_GUARD
  - PHASE2_TOKEN
  - PHASE2_ADMIN_SECRET
  - PHASE2_AGENT_SECRET
  - PHASE2_RECIPIENT_SECRET
  - PHASE2_OUTSIDER_SECRET

Copy the documented template and fill it in:  cp .env.phase2.example .env.phase2
Or provision a fresh instance (writes the file, including PHASE2_ISSUER_SECRET):  npm run deploy:phase2
```

Fixtures that encode real network shapes are committed and refreshed when the
code or the SDK beneath them changes:

- `tests/fixtures/contract-fixtures.json` — the guard's event vocabulary. Refresh
  with `npm run sync:fixtures` when the contracts repo's schema moves.
- `tests/fixtures/rpc/*.json` — real RPC payloads decoded by
  `tests/unit/rpc-fixtures.test.ts`. Refresh with `npm run capture:rpc-fixtures`
  after touching `src/telemetry.ts` or `src/invoke.ts`, or after upgrading
  `@stellar/stellar-sdk`. Provenance and capture details:
  `tests/fixtures/rpc/README.md`.

## Secrets

`PHASE2_ENV_FILE` (live testnet signing keys) and `NPM_TOKEN` (publish) are
maintainer-managed repository secrets. `.env.phase2` is gitignored — never commit it,
and never embed keys in a workflow or work around a missing secret with an alternate
name.

`PHASE2_ENV_FILE` must stay referenced in **exactly one workflow** —
`.github/workflows/live-suite.yml` — which is triggered only by `schedule` and
`workflow_dispatch`. Never add it to a workflow with a `pull_request` or
`pull_request_target` trigger: that would expose it to a forked pull request.
