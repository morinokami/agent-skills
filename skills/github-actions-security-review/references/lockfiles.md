# Workflow dependency lockfiles

Read this when the repository has `.github/workflows/actions.lock`, or when the task is to adopt, verify, or review one.

Checked in November 2026 against GitHub's documentation and `gh-actions-lock` 0.4.1. Lockfiles became generally available on 2026-10-28 on Free, Team, and Enterprise Cloud plans and do not exist on GitHub Enterprise Server. The CLI is pre-1.0, so `gh actions-lock --help` outranks this file on flags. GitHub also ships an agent skill for the CLI (`gh skill install github/gh-actions-lock`); if it is installed, prefer it for command detail.

## Reading a lockfile without tools

```yaml
version: 'v0.0.3'
workflows:
    '.github/workflows/ci.yml':
        - 'octo-org/deploy-action@v3.1.0'
dependencies:
    'octo-org/deploy-action@v3.1.0':
        ref: 'v3.1.0'
        commit: 'sha1-...'
        owner_id: 44036562
        repo_id: 197814629
        uses:
            - 'actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c'
```

- `workflows` lists the onboarded workflows. A workflow file missing from it is not protected at all, even though a lockfile exists: its tag and branch references still resolve at run time.
- A workflow's list holds the action references written in the workflow itself and those inside the `$/` actions it calls. What a remote action uses in turn is recorded under that dependency's `uses:`.
- For an onboarded workflow the runner executes `commit`, requires an entry for every action the workflow uses, rejects a commit that is not reachable from `ref` in the action's own repository, and compares `owner_id` and `repo_id` so that a deleted and re-registered repository name is caught.
- In a lockfile diff, a changed `commit` means different code will run, so review it like any dependency bump. A changed `owner_id` or `repo_id` means the name now belongs to a different repository: stop and investigate. The tooling does not notice a floating ref (`v4`, `main`) being moved back to an older commit in its history, so check the direction of the change yourself.

`scripts/inventory.py` does this reading for you. Per workflow it gives `onboarded_to_lockfile`. Per reference it gives `pin: "lockfile"` with the `locked_commit`, or `lockfile_entry: "not found"` when an onboarded workflow uses an action that has no entry, in which case the job fails at that step until the lockfile is regenerated. For the actions inside a local action it gives `locked_in_callers` and `not_locked_in_callers`, because that coverage depends on which workflow calls it. Without the script, make the same comparison by hand.

## What a lockfile does not cover

- Reusable workflow calls (`jobs.<id>.uses`) into other repositories. Pin those by full commit SHA. The actions inside the called workflow are covered only by a lockfile in its own repository.
- Local `./` actions, which are never followed or locked. If one uses remote actions, those need entries for the same workflow or the job fails when it reaches that step.
- Container images.
- Whether the locked code deserves trust. The first lock records whatever each tag pointed to that day.

A workflow that is not onboarded but pins every action by full SHA, as compiled agentic workflows do, is not an unpinned-action finding. It has to be onboarded only where the Require lockfile policy targets it.

## Commands

| Command | Writes files | Network | Purpose |
|---|---|---|---|
| `gh actions-lock --verify-local` | no | no | every `uses:` has an entry (coverage only, not provenance) |
| `gh actions-lock --verify` | no | yes | full check, the one to run in CI |
| `gh actions-lock --no-fix` | no | yes | read-only report |
| `gh actions-lock` | yes | yes | onboard workflows or repair the lockfile |
| `gh actions-lock --relock` | yes | yes | advance moved refs to current upstream commits |

- To see whether the extension is installed without going online, run `GH_NO_UPDATE_NOTIFIER=1 GH_NO_EXTENSION_UPDATE_NOTIFIER=1 gh actions-lock --help`; it fails when the extension is absent.
- In audit mode, `--verify-local` is fine when the extension is installed. `--verify` and `--no-fix` contact GitHub with the user's `gh` login, so ask first. The writing commands belong to fix mode.
- Add `--json` for parseable output on stdout; progress goes to stderr. Exit code 0 is clean, 1 means blocking findings, 2 means the tool itself failed.
- Three finding categories are security events, not chores: `repo-replaced` (the name now points at a different repository), `misleading-sha` (a ref made to look like a commit SHA), and `unreachable-pin` (the locked commit left the ref's history, through an upstream force-push or an edited lockfile). Report them and stop. Do not relock, and leave `--accept-moved` to the user, because it accepts exactly the state a tampered pin produces.

## Adopting or repairing a lockfile (fix mode)

- Before the first run, check that each `uses:` points at a version worth freezing.
- A run changes more than the lockfile. It narrows partial versions in the workflow files (`@v4` becomes `@v4.2.1`; `--no-narrow` keeps them), and with `--migrate-local-actions` it rewrites `./` references to `$/` in workflows and action files. Writes are all or nothing. Review and report the whole diff.
- Warn the user about one way this breaks CI: once a workflow is onboarded, the organization's or repository's allowed-actions list is matched against the locked commit SHAs, so entries written with a tag (`actions/checkout@v6`) stop matching. Whether such a list exists is a GitHub setting you cannot see.
- A blocking `local-action` error means a local `./` action uses remote actions. `--migrate-local-actions` is the recommended fix and `--ignore-local-actions` keeps `./` with a warning; both change behavior, so let the user choose.
- Never edit `actions.lock` by hand. Fix the workflow and rerun the command.
- After any later change to a `uses:` line in an onboarded workflow, or in a `$/` action it calls, the lockfile must be regenerated, or the job fails for the missing entry.
- To keep it current: Dependabot regenerates entries in its version-update pull requests for workflows that are already onboarded (it does not onboard new ones); a required CI check should run `gh actions-lock --verify` on pull requests (the `gh-actions-lock` repository has a template, `.github/workflows/verify-lockfile.yml`); and CODEOWNERS should cover `actions.lock`.

## Enforcement

These are GitHub settings, so list them as not verifiable locally. The Require lockfile policy blocks targeted workflows that are not onboarded, including a caller whose reusable workflow lives in a repository that is not onboarded. It is separate from the policy that requires full-length commit SHAs; an onboarded workflow satisfies both. Evaluate (dry-run) mode for policies exists only on Enterprise Cloud.

## Sources

- https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles
- https://docs.github.com/en/actions/how-tos/secure-your-work/lock-workflow-dependencies
- https://docs.github.com/en/actions/how-tos/administer/enforce-workflow-lockfiles
- https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution
- https://github.com/github/gh-actions-lock (README and `docs/troubleshooting.md`)
