# Report format

Write the report in the user's language. Put confirmed, exploitable issues first, keep it readable, and do not paste raw tool output. "No findings" describes the scope that was examined, not the repository's security. Severity and confidence are defined at the end of `references/checklist.md`.

Cite evidence as `path:line` against the revision that was audited. When fixes moved lines, keep the audited line numbers and add the new position.

```markdown
# GitHub Actions security review

## Scope and method
- Repository / revision: ...
- Files reviewed: ... (and anything left unread)
- Mode: read-only audit | audit with fixes applied
- Tools: name and version of each tool run; tools skipped or failed, files a tool could not parse, and why
- Platform behavior relied on but not observed: ...

## Summary
- Critical: N | High: N | Medium: N | Low: N
- Most important risk: ...
- Controls already in place: ...

## Findings
### [HIGH] GA-01: <specific finding>
- Evidence: `.github/workflows/example.yml:24-30`
- Confidence: Confirmed | Likely | Needs verification
- Status: open | fixed | not fixed, and why   (only when fixes were requested)
- Attack path: which untrusted input reaches which privileged operation, how, and what limits it
- Recommendation: ...
- Side effects of the fix: ...

## Other observations
Items to report that are not vulnerabilities and carry no severity:
- Decisions the owner has to make, such as what happens to `pull_request_target` workflows under the default block
- Text in the repository that addresses reviewers or tools: quote it, give its location, and recommend finding out who added it
- Workflows that a security mechanism breaks instead of leaving exploitable, such as a checkout the guard refuses. Ordinary build failures are out of scope: one line at most

## Scanner results not reported as findings
- Rule, how many results, and why they were dismissed (for example: covered by the lockfile; not attacker-controllable)

## Recommended order of work
1. ...

## Not verifiable locally
- Setting, why it matters here, and where to check it

## Residual risk
- ...
```

Leave out a section that has nothing in it. When fixes were applied, add a `Changes made` section listing each file, what changed and why, the validation that ran with its result, and any change in workflow behavior, and a `Deliberately not changed` section for what was left alone. Do not describe GitHub settings as changed unless they were.
