---
status: active
last_reviewed: 2026-06-13
---

# Upstream keyring follow-ups

## Summary

The upstream `99designs/keyring` backlog has a few useful fixes, but most open
PRs are either already covered in this fork or too stale to merge directly. This
plan tracks the work worth introducing into `lox/keyring` as small, reviewable
PRs.

The immediate goal is to improve existing backend behavior without taking on new
backends or a large macOS rewrite. Data Protection Keychain, Touch ID, and
1Password support remain valid future work, but they need fresh design rather
than a direct cherry-pick from upstream.

## Problem

Several backend failure modes are currently hard for callers to handle:

- macOS Keychain returns raw OSStatus errors for user cancellation, denied
  access, missing entitlements, and invalid owner edits.
- The Linux DBus-backed backends open DBus resources from package
  initialization, even when callers use a different backend.
- Secret Service empty-state and collection behavior has historically differed
  from other backends.
- WinCred has reports of nil credentials and unclear value-size failures.

Leaving these as raw backend quirks forces downstream projects to match error
strings, ignore confusing failures, or avoid the backend entirely.

## Goals

- Add stable, backend-neutral error handling where the public API needs it.
- Keep each backend fix small enough to review and validate independently.
- Preserve existing backend-specific errors under `errors.Is` where callers may
  already depend on them.
- Prefer tests around pure behavior and error mapping, with platform smoke
  coverage through CI where possible.

## Non-goals

- Do not import upstream PRs wholesale.
- Do not add Data Protection Keychain, Touch ID, 1Password, Passage, or LastPass
  support in these slices.
- Do not change the `Keyring` interface unless a later slice proves that an
  optional interface is insufficient.
- Do not make unsupported platform backends silently available.

## Current state

- Slice 1 landed in PR #7: macOS Keychain access-denied and user-cancelled
  OSStatus values now wrap `ErrAccessDenied` while preserving the raw platform
  error.
- `github.com/dvsekhvalnov/jose2go` is already at `v1.8.0`, covering upstream
  PR #141.
- `gopkg.in/yaml.v3` is already at `v3.0.1`, covering upstream PR #131.
- FileBackend `Remove` already returns `ErrKeyNotFound` for missing files,
  covering issue #125.
- The old Secret Service duplicate-collection path decoding fix from upstream
  PR #83 is already present in `secretservice.go`.
- The macOS keychain synchronizable cleanup has landed in `lox/keyring` PR #2.

## Delivery strategy

1. **macOS keychain typed access errors.**
   Add a public sentinel for access-denied/user-cancelled keyring operations and
   normalize relevant macOS Security framework statuses while preserving the raw
   OSStatus as a wrapped error. Cover upstream PR #119 and the error-handling
   part of issue #84. Repeated prompt behavior and prompt wording remain
   separate macOS follow-ups because they may require ACL or item-label changes.

2. **Secret Service DBus lifecycle.**
   Stop the Linux DBus-backed backends from opening DBus/libsecret resources
   from package initialization. Use lazy opener-time probing so importing
   keyring or using a different backend does not autostart DBus. Do not add a
   `Close` method for this slice: the current DBus calls use godbus' shared
   `SessionBus`, whose own docs say callers must not close it.

3. **Secret Service consistency pass.**
   Tighten empty-state, collection lookup, and default collection behavior so
   Secret Service behaves like the other backends for first-use `Get`, `Keys`,
   and `Remove` paths.

4. **WinCred correctness pass.**
   Harden nil credential handling, key listing, and oversized credential errors
   on Windows. Add tests that can run in the Windows CI matrix or isolate pure
   behavior behind a small helper.

## Verification

- Run `go test ./...` for fast local coverage.
- Run `go test -race ./...` when a slice touches concurrency, lifecycle, or
  platform-backed behavior.
- Run `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run`
  before publishing a PR.
- Use the GitHub Actions macOS, Linux, and Windows matrices as the final
  platform smoke test for PRs.

## Key learnings from pressure-testing

- The macOS Data Protection Keychain PR is directionally useful but depends on a
  personal `go-keychain` fork and lacks a signed-app test strategy. It belongs
  in a separate design plan.
- Adding a `Close` method to `Keyring` would be a breaking interface change. The
  Secret Service lifecycle slice should avoid that by removing eager DBus access
  first.
- Backend-neutral sentinels need to wrap, not replace, platform errors so
  existing callers can keep matching raw errors.
- Windows fixes should not be inferred from non-Windows behavior. The Windows CI
  matrix should be the proof point for that slice.
