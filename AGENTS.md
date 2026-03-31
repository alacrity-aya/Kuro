# AGENTS.md — Kuro Agent Work Guide

Purpose: practical guidance for coding agents in this repo.
Focus: correct commands, single-test workflows, style rules, and safe implementation behavior.

## Repository Snapshot
- Project: **Kuro** (eBPF-based distributed network simulator)
- Backend: Go (`cmd/`, `internal/`, `api/`)
- Data plane: eBPF C (`bpf/`)
- Frontend: React + TypeScript (`frontend/`)

## Canonical Command Sources
When docs conflict, trust these files first:
- `Makefile`
- `scripts/test.sh`
- `frontend/package.json`
- `frontend/eslint.config.js`

## Build & Generation Commands
Run from repo root:

```bash
make proto
make bpf
make generate
make build
make images IMAGE_TAG=dev
```

Notes:
- `make bpf` depends on `bpftool` and `/sys/kernel/btf/vmlinux`.
- `make build` builds both agent and controller binaries into `bin/`.

## Test Commands (Go / eBPF / K8s)
Unified runner from root:

```bash
./scripts/test.sh -std
./scripts/test.sh -bpf
./scripts/test.sh -k8s
./scripts/test.sh -benchmark
./scripts/test.sh -all
```

Useful flags:

```bash
./scripts/test.sh -std --verbose
./scripts/test.sh -std --no-cache
./scripts/test.sh -std --verbose --no-cache
```

Tag behavior (from script implementation):
- `-std`: excludes `bpf`, `k8s`, `benchmark`
- `-bpf`: compiles with `-tags=bpf`, runs binaries with `sudo`
- `-k8s`: runs with `-tags=k8s`, requires `scripts/setup_env.sh`
- `-benchmark`: uses `-tags="bpf,benchmark"`, executes with `sudo`

## Running a Single Test (Important)
Go examples:

```bash
go test -v ./internal/controller/k8s -run TestTrafficControlReconciler
go test -v ./internal/controller/k8s -run TestTrafficControlReconciler_Reconcile
go test -v ./path/to/package -run TestName
```

## Frontend Commands
Run in `frontend/`:

```bash
npm run dev
npm run build
npm run lint
npm run test
npm run test:run
npm run test:coverage
```

Single frontend test examples:

```bash
npx vitest run src/utils/topologyValidator.test.ts
npx vitest run -t "validateTopology"
```

## Style & Formatting Rules
### Go
- Follow `gofmt` output.
- Keep import blocks grouped by repository style:
  1. standard library
  2. local `kuro/...`
  3. external deps (`github.com/...`, `k8s.io/...`)
- Prefer explicit error returns over hidden control flow.

### TypeScript / React
- Lint policy is defined in `frontend/eslint.config.js`.
- Use explicit props/types; keep domain model alignment with `frontend/src/types/api.ts`.
- Keep imports tidy (external first, then internal).
- Preserve existing style (single quotes, semicolons, hook-based functional components).

### eBPF C
- Follow `bpf/.clang-format`.
- Keep verifier-sensitive logic conservative.

## Naming Conventions
- Go package names: lowercase, concise
- Go exported symbols: PascalCase
- React components/files: PascalCase
- Hooks: `useXxx`
- TS vars/functions: camelCase
- Preserve canonical label key: `kuro.io/node-group`

## Type Safety & Validation
- Never bypass type checks with suppression shortcuts.
- Validate form and YAML input before mutation calls.
- Keep frontend API payloads aligned with backend CRD/proto contracts.

## Error Handling Rules
- Never swallow errors.
- Frontend:
  - show actionable UI errors (`setError(...)`) for user-facing failures
  - keep `console.error` for failure diagnostics
  - avoid non-essential `console.log` in production paths
- Go:
  - return contextual errors
  - avoid panic for routine failures

## Test & Verification Discipline
For each change, verify minimally then expand:
1. Run targeted tests for changed behavior
2. Run relevant lint/type checks
3. Run broader suites only when needed

Recommended minimums:
- Go-only change: targeted `go test` + `./scripts/test.sh -std`
- Frontend-only change: `npm run lint` + targeted `vitest`
- Cross-stack change: verify both sides

## Cursor / Copilot Instruction Files
Checked for:
- `.cursorrules`
- `.cursor/rules/`
- `.github/copilot-instructions.md`

Current status: **none found** in this repository.

## Practical Guardrails
- Prefer small, surgical diffs.
- Do not alter API/CRD semantics unintentionally.
- Reuse existing patterns before introducing new abstractions.
- If command behavior changes, update docs.
- In final report, state exactly what was verified and outcomes.

## High-Value Files
- `internal/controller/controller.go`
- `internal/controller/api/server.go`
- `internal/controller/k8s/*.go`
- `internal/agent/**`
- `bpf/tc.c`, `bpf/include/*`
- `frontend/src/pages/*`
- `frontend/src/stores/*`

Use this as operational guidance; source code remains the ultimate authority.
