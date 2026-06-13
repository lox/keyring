# AGENTS

- Prefer conventional commit messages; if a commit message is revised after push, use force-push with lease when allowed by policy.
- Before creating Codex-authored commits, run `git-assume bk-codex`, then use plain `git commit` without `-S`. This identity is intentionally unsigned so Codex does not block on 1Password signing approval.
- Use `lox/` as the default branch prefix.
- Open PRs against `origin` / `lox/keyring` by default; only target `upstream` / `99designs/keyring` when explicitly requested.
- Do not prefix PR titles with `[codex]`.
- Prefer PR titles in the form `type: Summary`, for example `ci: Isolate cleanroom cache in CI`.

## Pull Request Descriptions

- Start with the problem or motivation, not a changelog.
- Describe the user or developer impact of the change.
- Include concrete examples when behavior, configuration, or user-facing output changes.
- Keep implementation details focused on what reviewers need to understand.
- Don't include the validations section, it's too noisy
- Only use draft PR's if it's a work in progress
