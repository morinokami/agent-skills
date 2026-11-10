# Audit checklist

Work through the areas that apply to the repository. Each item is a question to answer from the source, not an automatic finding: severity depends on who can reach the path and what it yields, and the scale is at the end of this file. Platform behaviors named here (checkout guard, default block, cache modes, self-repository syntax, lockfile onboarding) are described in SKILL.md.

## A. Who can start what

- List each workflow's triggers and who can fire them. These events run with the base repository's token and secrets yet can be started, or have their payload shaped, by people without write access: `pull_request_target`, `issue_comment`, `issues`, `discussion`, `discussion_comment`, and `workflow_run` (as untrusted as the workflow it follows). `pull_request` from a fork is the safe default: read-only token, no secrets.
- Every `pull_request_target` workflow is subject to the default block if the repository is public. List it as a decision the owner has to make, whatever the workflow does.
- An `if:` is access control only when it tests something the attacker cannot set. `github.actor` names whoever caused the latest event, not the author of the code being run, so `github.actor == 'dependabot[bot]'` on a privileged trigger can hold for an attacker's pull request. The author is `github.event.pull_request.user.login`. Also check `contains()` and `startsWith()` tests on branch names, titles, and labels, which outsiders often control.
- Approval gates (a label, a `/command` comment, an environment review) approve what the approver saw. If the job then resolves a branch name or `refs/pull/N/head` at run time, the author can push between approval and execution. Check that it checks out the exact approved commit: the SHA in the event payload for label and review events; for comment commands, a SHA carried in the command or compared with the pull request head at approval time. A label that stays on the pull request approves every later push when the workflow also runs on `synchronize`. Also list everything that can open the gate: any workflow or agent holding a token that can label or comment can do it on the attacker's behalf (`issues: write` is enough to label a pull request). An event caused with the workflow's own `GITHUB_TOKEN` starts no new run, so a label applied that way takes effect at the next push; one applied with a personal or App token takes effect at once.
- For comment-triggered jobs, check that the commenter's permission is verified (`author_association` or a permission API call) before anything privileged happens, and that `issue_comment` on a pull request is distinguished from one on an issue.

## B. Untrusted code reaching a privileged job

- The classic "pwn request": a privileged job obtains pull request code and then runs anything from it. Obtaining can be `actions/checkout` with `ref:` or `repository:` taken from the pull request, `git fetch`, `gh pr checkout`, or an artifact download. Running is broader than a build step: `npm install` and other installers execute lifecycle scripts, test runners and linters load configuration and plugins from the tree, `make`, `pip install -e .`, and any `uses: ./...` local action are all execution.
- For each such checkout, work out the effective `actions/checkout` version (from the tag, the version comment beside a SHA, or the lockfile) to see whether the checkout guard applies. `allow-unsafe-pr-checkout: true` means someone opted out on purpose: verify the code is handled only as data.
- `uses: ./path` after an untrusted checkout runs the pull request's copy of the action. On github.com, `uses: $/path` removes that risk for actions meant to come from the repository itself.
- `workflow_run`: find the upstream workflow and whether forks can trigger it. Everything it uploaded is attacker-controlled: check that artifacts are extracted outside the workspace (archive entries can overwrite files), never executed, and that pull request numbers or SHAs are taken from `github.event.workflow_run`, not from files inside the artifact.

## C. Untrusted text reaching an interpreter

- `${{ }}` is expanded into the script before the shell or JavaScript engine parses it, so quoting inside the script does not help. Look for expansions inside `run:`, `actions/github-script` `script:`, and any `with:` input the action evaluates as code or as a template.
- Attacker-controlled sources: titles, bodies, and comments of issues, pull requests, discussions, and reviews; branch names (`github.head_ref`); commit messages and author names; file names from changed-file listings; `inputs.*` of reusable workflows and composite actions when callers pass such values through; and step outputs derived from any of these.
- Moving the value into `env:` removes the expansion, but the script must still quote the variable and must not use it as a command, option, path, or `eval` input unchecked.
- Writing untrusted values to `$GITHUB_ENV` or `$GITHUB_PATH` carries them into later steps: variables such as `LD_PRELOAD`, `NODE_OPTIONS`, or `BASH_ENV`, or a directory prepended to the path, turn into code execution. A value containing a newline can also inject extra entries into `$GITHUB_OUTPUT`.

## D. Token, secrets, identity

- Expect `permissions: {}` (or read-only) at the top of each workflow and narrow grants on the jobs that need them. When a workflow declares none, it gets the repository default, which may be read-write and cannot be seen locally. Setting any scope makes all unlisted scopes `none`.
- Every action in a job can read `github.token`, whether or not it is passed in `with:`. Judge third-party actions in jobs that hold write scopes or secrets accordingly.
- `actions/checkout` keeps the token for later git commands unless `persist-credentials: false`. Flag it where later steps run untrusted code or upload the workspace as an artifact. From v6 the token is kept under `$RUNNER_TEMP` instead of `.git/config`, which narrows but does not remove the exposure.
- Map which jobs can see which secrets. Flag `secrets: inherit` on reusable workflow calls (it hands over every secret), `toJSON(secrets)`, secrets set as workflow-level or job-level `env:` when one step needs them, and deploy credentials that are repository secrets when an environment with required reviewers could hold them. Log masking is not a boundary: encoded or structured values are not redacted.
- For personal access tokens and GitHub App tokens, note their scope and every step that can read them.
- `id-token: write` belongs only on the job that deploys or publishes. The cloud-side trust policy has to pin repository and branch, tag, or environment (and `job_workflow_ref` when a reusable workflow deploys). That policy is usually outside the repository, so list it as not verifiable unless infrastructure code is present.
- For package publishing, prefer the registry's trusted publishing (OIDC) over long-lived tokens; npm, PyPI, RubyGems, crates.io, and NuGet support it.

## E. Dependencies

- Remote actions: onboarded to the lockfile, or pinned to a full commit SHA. Reusable workflow calls: full SHA always. Container images, including `docker://` actions, job `container:`, and `services:`: `@sha256:` digest.
- A version comment beside a SHA is a claim, and reasoning about which release a pin is (the checkout guard, for instance) rests on it. With network access, confirm the SHA is that tag.
- A pin fixes which code runs, not whether it deserves trust. Note actions that are archived, unmaintained, or have published advisories. Confirming that a SHA belongs to the action's own repository and not to a fork needs network access (zizmor's online `impostor-commit` audit does it).
- Dependabot does not raise vulnerability alerts for SHA-pinned actions. Without a lockfile or version updates covering `github-actions`, SHA pins go stale silently.
- Dependabot version updates wait 3 days after a release by default (`cooldown`), so a missing `cooldown` block is not a finding; `default-days: 0` or a broad `exclude` is. Older scanners still flag the missing block.
- Code fetched at run time: `curl | sh`, installers without a version or checksum (`pip install x`, `npm install -g x`, `go install ...@latest`), and unfrozen package installs (`npm install` where `npm ci` would do). Weigh these by the credentials present in the job.

## F. Caches, artifacts, runners

- Cache poisoning needs a writer and a reader. Writers: any job under a low-trust trigger that declares `cache-mode: write` or `write-only`, and reusable workflows called from such a trigger that request write access (capped by `cache-mode: read` on the calling job). Readers that matter: release, publish, and deploy jobs. Restores are often implicit in `setup-*` actions. Recommend `cache-mode: none` on those jobs.
- Under `workflow_run`, the checkout guard keeps fork code out of a write-capable job but not branches inside the repository, so unreviewed branches, Dependabot's included, still reach it.
- Anyone who can open a pull request can read caches from the base branch, so cached paths must not contain secrets.
- Artifacts: check what a job run on untrusted input uploads and who consumes it, and that uploads do not include `.git`, credential files, or the whole workspace.
- Self-hosted runners: in a public repository a fork pull request can run code on them unless fork approval is configured. Check whether runners persist between jobs and what they can reach (cloud metadata endpoints, internal services). Ephemeral runners and runner groups limit the damage.

## G. AI agents in workflows

Applies to agentic workflows (`gh aw` sources and their compiled `.lock.yml`) and to any step that runs a coding agent, such as `anthropics/claude-code-action`, `openai/codex-action`, `google-github-actions/run-gemini-cli`, or an agent CLI in `run:`. Issue text, comments, diffs, and fetched pages become instructions the agent may follow, and no prompt wording makes untrusted text safe. Judge these by privilege:

- Who can make the agent run, and on whose text? Look for options that admit users without write access or arbitrary bots (in `claude-code-action`, `allowed_non_write_users` and `allowed_bots`).
- What can the agent do with a hijacked instruction: shell and tool access, token scopes, other secrets in its environment (the model API key included), network egress?
- Where does its output go? Comments, commits, labels, and pull requests are both a way to leak data and a second injection point for whatever reads them next.
- Does an untrusted checkout sit in the agent's working directory? Agent CLIs load instruction and configuration files from there (`CLAUDE.md`, `AGENTS.md`, `.claude/`, MCP configuration), so a pull request can reconfigure the agent.
- In `gh aw` sources, treat every relaxed default as a trust decision to report: `strict: false`, wider `roles` or bot admission, a disabled sandbox, firewall, or threat detection, added `network` domains, write permissions on the agent job, and custom jobs or steps that hold secrets. The intended shape keeps the agent job read-only and applies writes through `safe-outputs` jobs. A workflow compiled with `strict: false` refuses to run in a public repository.
- A compiled `gh aw` workflow normally has separate jobs: `activation`, `agent`, and, when safe outputs are configured, `detection` and one job per safe output. When the agent job itself holds write permissions or those jobs are missing, say in the agent finding that the containment the source implies is not visible in what runs. Whether the compiled file matches its source cannot be confirmed without the compiler: compare triggers and permissions by eye, and list it as not verifiable (recompiling with `gh aw compile` should leave no diff).

## H. Governance

- CODEOWNERS should cover `.github/workflows/`, action definitions, and `actions.lock`. The file only requests reviews; enforcement needs a branch rule that requires code owner approval.
- List for manual verification, since none of it is in the checkout: repository visibility; default `GITHUB_TOKEN` permissions; whether Actions may create and approve pull requests; approval requirements for fork pull request runs; Actions policies (event rules, including whether `pull_request_target` is allowed and for which workflow files, actor rules, Require lockfile, allowed actions, required SHA pinning); branch rules; environments and their reviewers; where each secret is scoped; runner groups; and whether Dependabot alerts and code scanning for Actions are enabled.

## Rating findings

Severity follows from the path, not from the pattern that matched, and not from a scanner's label.

- **Critical**: an outsider, with no help from a maintainer, can run code or direct an agent in a job that holds secrets, a write token, signing keys, or deploy credentials. An outsider is anyone without write access: any GitHub user for a public repository, anyone with read access otherwise.
- **High**: the same outcome, but it needs one plausible maintainer action (applying a label, typing a command, approving a run) or another precondition the attacker can arrange. Also confirmed script injection, or untrusted input crossing into a privileged job, where less is at stake.
- **Medium**: exploitable only if something outside the attacker's control also fails, such as a compromised upstream repository behind a mutable reference, or a cache or artifact flow that needs a second weakness. Broad permissions without a demonstrated path belong here too. Say who controls the upstream: unpinned code from an unrelated third party running beside secrets is the worst case and may be rated High.
- **Low**: hardening with little current exploitability.

Steering an agent that has a shell or write-capable tools counts as running code. Lower the severity when a mitigation you can see (permissions, job separation, lockfile coverage, environment protection) blocks the path, and name it. Do not lower it for a mitigation that is not in force yet or that depends on a setting you cannot see; mention that one instead.

Rate each finding on its own path. When another open finding removes one of its preconditions, for example by letting the attacker apply the gating label, keep the rating, describe the chain in both findings, and let the summary's most important risk reflect the combined effect.

Some things must be reported but are not vulnerabilities, and get no severity: a decision the owner has to make (the default block), text in the repository that addresses reviewers or tools, and a workflow that is broken rather than exploitable. They go under "Other observations" in the report.

Confidence is **Confirmed** when the whole path is visible in the source, **Likely** when one link is inferred, and **Needs verification** when the path exists only under a GitHub setting you could not see, such as repository visibility; rate such a finding for the case where the path is open and name the setting. When two of these apply, use the weaker. For a finding about configuration, such as a mutable reference or a broad permission, Confirmed means the configuration is as described; the hypothetical compromise is what the severity accounts for.

A conclusion is at most Likely when it rests on platform behavior described in this skill but not observed, for example that the checkout guard stops a fork checkout, or on a version comment beside a SHA. Say what it rests on and how the user can confirm it, such as the run history or `git ls-remote`.
