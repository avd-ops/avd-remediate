# 0002. Normalize CRLF to LF when computing and verifying `contracts/PINS.json` hashes

- **Date:** 2026-11-11

## What happened
After copying `contracts/calibration.json` and `contracts/workload-tiers.json` from a local Windows clone (`core.autocrlf=true`) into `avd-remediate`, their raw working-tree bytes contained `\r\n` line endings when `contracts/PINS.json` was generated. When Git staged and pushed those files to Linux CI (`ubuntu-latest`), Git normalized them to `\n`, causing `tests/locks.test.mjs` to fail on `contracts/calibration.json` SHA-256 verification.

## Cause
`tests/locks.test.mjs` hashed raw file bytes (`fs.readFileSync(fullPath)`) without normalizing `\r\n` to `\n`, so a file copied with CRLF in a Windows working tree before Git's index normalization had a different digest than a clean Linux checkout.

## Fix
Updated `tests/locks.test.mjs` to normalize `\r\n` to `\n` (`fs.readFileSync(fullPath, 'utf8').replace(/\r\n/g, '\n')`) before computing SHA-256 digests, and updated `contracts/PINS.json` with the canonical LF digests for `contracts/calibration.json` and `contracts/workload-tiers.json`.

## Guard
`tests/locks.test.mjs` verifies that both LF and CRLF representations of vendored contract files hash identically to the pinned digest in `contracts/PINS.json`.
