# Remediation patterns

Read this before writing recommendations and before any edit. The examples are shapes to adapt, not text to paste: follow the repository's own conventions for pinning style, action versions, and YAML layout.

## Before editing

- Do not hand-edit generated files. `actions.lock` comes from `gh actions-lock`. A `<name>.lock.yml` with a `<name>.md` beside it comes from `gh aw compile`: change the `.md` and recompile. If the generator is not installed or not permitted, do not leave source and output out of sync; describe the change and the command for the user to run.
- Write only commit SHAs you resolved yourself, for example with `git ls-remote https://github.com/OWNER/REPO 'refs/tags/TAG^{}' 'refs/tags/TAG'` (when a `^{}` line is printed, it is the commit behind an annotated tag). That needs network permission. If you cannot resolve a SHA, leave the tag in place and report it.
- If a fix needs an action the workflow does not use yet and you cannot pin it the way the repository pins (no network for a SHA, no generator for the lockfile), prefer a fix that adds no new reference, or ask for network access. Do not add a floating tag to a privileged workflow silently.
- Changing an action's major version can change its behavior or inputs. Keep the version in use unless the user asked for an upgrade.
- Choose the smallest change that closes the path and keeps what the user asked to preserve. When closing the path takes a feature away from some users, such as previews for fork pull requests, make the change, state exactly what stops working and for whom, and put the fuller redesign in the recommendations.
- A fix that cannot be completed in this session stays open. Say so in the report and name an interim step the user can take, such as disabling the workflow (`gh workflow disable <file>` or the Actions tab).

## Least-privilege token

```yaml
permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
```

Each job then has to list every scope it uses, so read what its steps call before choosing. `persist-credentials: false` breaks a later `git push` in the same job.

## Script injection

Unsafe, because the title becomes part of the script:

```yaml
- run: echo "${{ github.event.pull_request.title }}"
```

Safer, because the value arrives as data:

```yaml
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: printf '%s\n' "$PR_TITLE"
```

The same applies to `actions/github-script`: pass the value through `env:` and read `process.env.PR_TITLE` in the script. Inside the script the variable still needs quoting, and still must not become a command name, an option, a path, or `eval` input without validation.

## A privileged job that must not run fork code

When a job has to keep its secrets and only needs to work for branches of the repository itself, restrict it:

```yaml
jobs:
  preview:
    if: github.event.pull_request.head.repo.full_name == github.repository
```

Compare the full name. `head.repo` is null once a fork has been deleted, and `head.repo.fork == false` passes in that case, because null and false compare as equal in workflow expressions. This guard removes the feature for fork pull requests, and it leaves the repository's own unreviewed branches able to run with the secrets, so report both.

## Privileged work on fork pull requests

Split the workflow in two so that untrusted code and credentials never share a job.

- The untrusted half runs on `pull_request` with a read-only token and no secrets. It builds and tests the fork's code and may upload results as an artifact.
- The privileged half runs on `workflow_run` for that workflow. It never checks out or executes pull request code. It downloads the artifact into `${{ runner.temp }}`, treats the contents as data to validate (a pull request number must be numeric, for instance), and takes the identity of the run from `github.event.workflow_run`, not from the artifact.

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

permissions: {}

jobs:
  report:
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    permissions:
      actions: read          # download the artifact
      pull-requests: write   # post the result
    steps:
      - uses: actions/download-artifact@v8
        with:
          name: result
          path: ${{ runner.temp }}/result
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
```

A `pull_request_target` workflow that only labels or comments from the event payload, with no checkout of pull request code, can stay as it is. In a public repository it then needs an admin to allow that workflow file in an Actions event policy. That is a settings change you cannot make from the repository, so say so in the report.

## Comment commands

An `issue_comment` job should establish three things, in this order, before any privileged step:

1. The comment is on a pull request: `github.event.issue.pull_request` is set.
2. The commenter may do this. `gh api "repos/$GITHUB_REPOSITORY/collaborators/$COMMENTER/permission" --jq .permission` returns `admin`, `write`, `read`, or `none`; require `admin` or `write`. `author_association` describes a relationship, not a permission level, so it is the weaker test.
3. Which commit is meant. Resolve the head once (`gh pr view "$PR_NUMBER" --json headRefOid,isCrossRepository`), refuse a head in another repository if the job executes the code, and check out that SHA instead of asking for the pull request's head again later.

Pass the comment body, the login, and the number through `env:`. The job token cannot push to a fork, so a command that commits back loses nothing by refusing forks.

## Label and approval gates

A label approves a pull request, not a commit. Either drop `synchronize` from the gated workflow so every run needs a fresh `labeled` event, and remove the label whenever new commits arrive, or replace the label with a deployment environment that has required reviewers, which approves one run of one commit. In both cases check out the SHA from the event payload.

## Reusable workflow calls

```yaml
jobs:
  notify:
    permissions: {}
    uses: octo-org/shared/.github/workflows/notify.yml@<40-hex-sha> # v1.2.0
    secrets:
      SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
```

Pass the secrets the called workflow needs by name instead of `secrets: inherit`, pin the call by full SHA, and set `permissions` on the calling job: the called workflow can reduce the token's scopes but never raise them.

## Pinning

- Where the repository uses a lockfile, onboard the remaining workflows as described in `references/lockfiles.md`.
- Otherwise pin remote actions to a full SHA with the version in a comment on the same line, which Dependabot keeps up to date: `uses: actions/checkout@<40-hex-sha> # v7.0.1`.
- Reusable workflow calls take a full SHA in both cases.
- Container images take a digest: `image@sha256:...`.
- For actions in the same repository on github.com, `uses: ./path` can become `uses: $/path`. This changes behavior when a job deliberately runs the checked-out copy of the action (under `pull_request_target` it switches from the pull request's copy to the base branch's), it needs runner 2.336.0 or later (check self-hosted runners), and it does not work on GitHub Enterprise Server.

## Code fetched at run time

Replace `curl ... | sh` with a download of a fixed version that is verified before use, or with a pinned action or a package manager with a lockfile:

```yaml
- run: |
    curl -fsSLo tool.tar.gz https://example.com/releases/tool-1.2.3-linux-amd64.tar.gz
    echo "<sha256-of-that-file>  tool.tar.gz" | sha256sum -c -
    tar -xzf tool.tar.gz
```

Take the checksum from the project's release page, not from the same server at run time.

## Publishing credentials

Where the registry supports trusted publishing, the publishing job needs `id-token: write` and no long-lived token: the registry is told which repository, workflow file, and environment may publish. That registration is done on the registry's side by the user, so recommend it and leave the token in place until it exists.

## Caches

```yaml
jobs:
  release:
    cache-mode: none
```

Use `cache-mode: none` on release, publish, and deploy jobs. Under low-trust triggers, remove `cache-mode: write` and let a `push`-triggered workflow fill the cache, and put `cache-mode: read` on jobs that call reusable workflows.

## Agent steps

Reduce privilege, since rewording the prompt does not help. Restrict who can trigger the agent. Give its job the smallest token scopes and no secret except the model credential. Keep untrusted checkouts out of its working directory. Have the agent job produce a proposal as an artifact or structured output, and let a separate job with write access apply it after validation or human approval.

For `gh aw` workflows that shape is built in. The agent job stays read-only and a safe output applies the change from a fixed list:

```markdown
---
on:
  issues:
    types: [opened]
permissions:
  contents: read
  issues: read
safe-outputs:
  add-labels:
    allowed: [bug, enhancement, question]
    max: 1
---
```

Leave `strict:` at its default, give `tools:` and `network:` only what the task needs, and keep untrusted text out of `${{ }}` expressions in the prompt. Then run `gh aw compile`, which may contact GitHub to resolve action pins it has not cached, and review the regenerated `.lock.yml` as new code.

## Closing checks

1. Read `git diff` and `git status --short`: only the intended files changed, with no unrelated reformatting or stray files.
2. Rerun the scanners from step 2 of the procedure and compare with the earlier run. Keep both outputs in a temporary directory, not in the repository. A scanner that never flagged the problem cannot confirm its fix, so re-read the changed logic as well.
3. If a `uses:` line changed in a workflow that is onboarded to the lockfile, or in a `$/` action it calls, regenerate the lockfile or tell the user it must be regenerated before merge.
4. Report what changed and why, any change in workflow behavior, what could not be tested locally (events do not fire locally; settings and cloud trust policies are out of reach), and what is left for the user: policy changes, generator commands, and rotating any secret that an exploitable path may already have exposed. Fixes to `pull_request_target`, `issue_comment`, and `workflow_run` workflows take effect only once they are on the default branch.
5. Do not push, open pull requests, or trigger runs unless asked.
