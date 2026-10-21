# Instructions for AI agents

Repository of **hallpass**: an interactive sandbox for shells, coding
agents and Kubernetes pods. It mediates file writes, program execution
and network connections, and asks the user. Read `README.md`, then
`docs/how-it-works/` and `docs/devel/README.md`. If `AGENTS.local.md`
exists, follow it too.

## Layout

- `cmd/hallpass`: the CLI (supervisor, prompts, session API, e2e tests).
- `cmd/hallpass-node`: the Kubernetes node agent (NRI plugin).
- `cmd/hallpass-request`: the static C helper a sandboxed program uses to
  ask in advance.
- `cmd/headlamp-wasm`, `headlamp/`: the Headlamp plugin and its WASM
  client.
- `internal/`: `seccomp` (seccomp-notify, lite mode), `lsm` and `bpf/`
  (BPF-LSM, strict mode; the compiled objects are committed, rebuilt with
  `make generate`), `monitor`, `rules`, `policy`, `answer`, `ui`, `web`,
  `sessionapi`, `programs`...
- `api/`: protobuf of the session API (generated code committed).
- `docs/`: the user documentation (mkdocs, published); `docs/devel/`:
  developer docs, not published.
- `test/kind`: the Kubernetes e2e test. `demos/`, `website/`: videos and
  site extras.

## Tests

From the cheapest to the most complete:

1. `gofmt -l .`, `go vet ./...`, `go test ./...`: no root needed. Before
   every commit.
2. `go test -exec sudo ./...`: the e2e tests, compiled as the user, run as
   root. Strict-mode tests skip unless BPF-LSM is active (`lsm=...,bpf` on
   the kernel command line); `HALLPASS_REQUIRE_LSM=1` makes them fail
   instead.
3. `make test-vm KERNEL_VERSION=7.2.8`: the tests in a VM booting a
   ci-kernels kernel with BPF-LSM (needs vimto and qemu; without
   `/dev/kvm` it falls back to emulation, much slower). Strict mode needs
   6.12 or later.
4. `make test-headlamp`, `make test-kind`, `make test-headlamp-kind`: the
   plugin and the Kubernetes e2e (docker, kind, kubectl).
5. `mkdocs build --strict` when `docs/` changes.

GitHub Actions (`.github/workflows/test.yml`) runs 1 and 3 on kernels
6.1 to 7.2 on every push. Each commit of a series must build and pass
`go vet` (`git rebase -x 'go build ./... && go vet ./...'`).

A failing test is fixed in the code, or the test is fixed with a reason;
never loosen a test only to make it pass.

## Conventions

- Go, formatted with `gofmt`; files start with the SPDX header used in the
  rest of the tree.
- Commit author and `Signed-off-by:` (DCO): the human contributor
  responsible for the change, never an LLM. The LLM is credited in a
  trailer (`Co-authored-by:`, `Assisted-by:`...).
- Commit titles `area: subject` (`monitor: ...`, `docs: ...`); the body
  says why.
- Documentation changes go with the code change that needs them.
- User-facing words: the operations are `write`, `exec`, `connect`;
  answers are explained in `docs/answers/`.

## Safety

- Nothing reaches `main` and no pull request is merged without a
  maintainer's explicit go.
- No destructive git operations (`reset --hard`, `clean -f`, force-push
  of shared branches) without explicit instruction.
- No secrets in the repository.
- Tests must not need network access beyond what CI has (Docker Hub and
  ghcr.io for images, the Go module proxy).
