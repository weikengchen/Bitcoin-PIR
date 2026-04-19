# Publishing

This document is the operator's runbook for publishing the BitcoinPIR
crates to [crates.io](https://crates.io) and the `pir-sdk-wasm` package
to [npm](https://www.npmjs.com).

It is **not** yet a press-the-button runbook: several blockers must be
resolved first. Each blocker is listed below with a suggested fix.

## Publishable artefacts

| Artefact                          | Registry   | Status                                              |
|-----------------------------------|------------|-----------------------------------------------------|
| `pir-core`                        | crates.io  | 🟢 Ready (no git deps, no path-only deps).          |
| `pir-sdk`                         | crates.io  | 🟢 Ready (path dep on `pir-core` only).             |
| `pir-runtime-core`                | crates.io  | 🟡 Blocked — git dep on `libdpf`.                   |
| `pir-sdk-client`                  | crates.io  | 🟡 Blocked — git deps on `libdpf` / `harmonypir`.   |
| `pir-sdk-wasm` (as a crate)       | crates.io  | 🟡 Blocked — transitively via `pir-sdk-client`.     |
| `pir-sdk-wasm` (as npm package)   | npm        | 🟢 Ready (wasm-pack bundles all Rust deps).         |
| `pir-sdk-server`                  | crates.io  | 🟡 Blocked — transitively via `pir-runtime-core`.   |

🟢 = ready; 🟡 = blocked, unblocking is tracked below; 🔴 = needs
upstream refactoring, no ETA.

## Blocker 1 — git dependencies on `libdpf` / `harmonypir`

### Current state

`pir-sdk-client` pulls `libdpf` directly and `harmonypir` transitively
(through the `path`-dep on the workspace-internal `harmonypir-wasm`
shim) from GitHub:

```toml
# pir-sdk-client/Cargo.toml
libdpf = { git = "https://github.com/weikengchen/libdpf.git" }

# harmonypir-wasm/Cargo.toml (path dep from pir-sdk-client)
harmonypir = { git = "https://github.com/Bitcoin-PIR/harmonypir.git",
               rev = "a849dedfe0b0ab283c7c9ad9e20f8775b01b4543",
               default-features = false }
```

crates.io requires all dependencies to be resolvable from the registry
(or be `optional = true` + gated behind a feature that's off in the
default-features set). Git deps in the non-optional path fail the
`cargo publish` sanity check even with `--allow-dirty`.

### Fixes (in increasing order of work)

1. **Publish `libdpf` and `harmonypir` to crates.io first.**
   Both crates are owned by weikengchen / Bitcoin-PIR. A single pass
   of `cargo publish` on each, followed by updating
   `pir-sdk-client/Cargo.toml` and `harmonypir-wasm/Cargo.toml` to
   registry versions with a pinned semver range, unblocks
   `pir-sdk-client`. `libdpf` currently has no pinned `rev` — pin one
   before publishing to avoid a floating-HEAD supply-chain risk.

2. **Vendor the code into `pir-core`.** Move the ≈1.5 kLOC
   `libdpf` / `harmonypir` cores into `pir-core` as submodules.
   Heavier surgery but produces a self-contained publishable crate
   with no external git deps. Only pursue if #1 stalls on upstream
   coordination.

### Note on the `onion` feature

The `onion` feature is **not** a blocker:

```toml
onionpir = { git = "...", rev = "...", optional = true }
```

Because `onion` is off by default, crates.io ignores the git URL when
verifying `default-features` — publishing `pir-sdk-client` with the
`onion` feature still present is legal, it simply means `cargo install
pir-sdk-client --features onion` fails on the registry copy (same as
if the user tried `--features onion` on a crates.io-only machine). If
the `onionpir` crate ever lands on crates.io, switch the git URL to a
semver range and `cargo install … --features onion` starts working
from the registry too.

## Blocker 2 — `pir-sdk-server` depends on internal binary crates (RESOLVED)

### Resolution

Extracted the shared server runtime primitives into a new publishable
library crate `pir-runtime-core` (≈2 kLOC: `protocol` wire format,
`table` mmap'd cuckoo reader, `eval` DPF evaluation, `handler` request
dispatch). Both `pir-sdk-server` and the workspace-internal `runtime/`
binary crate now depend on `pir-runtime-core` instead of maintaining
parallel copies. `pir-sdk-server` dropped its unused `build` dep and
the `publish = false` gate.

Verification: `cargo package --list -p pir-runtime-core` and `-p
pir-sdk-server` both produce clean tarballs with the expected metadata
files. Full workspace test surface preserved:
- `pir-core --lib` 25/25
- `pir-sdk --lib` 56/56
- `pir-sdk-client --lib` 125/125
- `pir-sdk-wasm --lib` 51/51
- `pir-sdk-server --lib` 0/0 (unchanged — no library tests)
- `pir-runtime-core --lib` 0/0 (library-only, no unit tests in the
  extracted modules — all semantic coverage lives in `pir-core`
  and end-to-end coverage lives in the `runtime/` bin integration
  tests, neither affected by the code move).

`pir-sdk-server` is now blocked only transitively via Blocker 1
(`libdpf` git dep in `pir-runtime-core`). Once `libdpf` lands on
crates.io, the publish order is:

```
pir-core → pir-sdk → pir-runtime-core → pir-sdk-server
```

🔒 PIR invariants preserved. The extraction is a pure code move; the
wire format, slot layout, DPF evaluation, and request-dispatch
semantics are byte-identical. K=75 INDEX / K_CHUNK=80 CHUNK /
25-MERKLE padding continues to be enforced in `pir-sdk-client`, and
`pir-runtime-core` is the server-side counterpart that answers padded
queries uniformly.

## Publish order

Once the blockers above are cleared, publish in this order to respect
the dependency graph:

1. `pir-core` (no workspace deps).
2. `pir-sdk` (depends on `pir-core`).
3. `libdpf`, `harmonypir` (upstream — see Blocker 1).
4. `pir-runtime-core` (depends on `pir-core` + `libdpf`).
5. `pir-sdk-client` (depends on `pir-core`, `pir-sdk`, `libdpf`,
   `harmonypir`).
6. `pir-sdk-wasm` (depends on everything above).
7. `pir-sdk-server` (depends on `pir-core`, `pir-sdk`,
   `pir-runtime-core`).

Between each step, wait ~30 s for crates.io's index propagation
before the next `cargo publish` so Cargo can resolve the
just-published dep.

## crates.io publishing — per-crate checklist

For each crate:

1. **Update version** in the crate's `Cargo.toml`. Pre-1.0: bump
   patch for bug fixes (`0.1.0` → `0.1.1`), minor for new APIs
   (`0.1.0` → `0.2.0`). Workspace crates currently ship in lockstep
   at the first release, with per-crate semver freedom afterward.

2. **Update `CHANGELOG.md`**: move the `Unreleased` section's contents
   under a new version heading, add a fresh empty `Unreleased`.

3. **Verify clean package**: `cargo package -p <crate> --list` to see
   what ships, `cargo package -p <crate>` to build the tarball.
   Sanity-check: the tarball should include `LICENSE-MIT`,
   `LICENSE-APACHE`, `README.md`, `CHANGELOG.md`, and only the `src/`
   / `build.rs` / `Cargo.toml` / `Cargo.lock` files (not the whole
   workspace).

4. **Dry run**: `cargo publish -p <crate> --dry-run`.

5. **Publish**: `cargo publish -p <crate>`.

6. **Tag the release**: `git tag -s <crate>-v<version> -m "..."`,
   `git push origin <crate>-v<version>`.

## npm publishing (`pir-sdk-wasm`)

wasm-pack does **not** copy every field from `Cargo.toml` into the
generated `pkg/package.json`. The missing fields (repository,
homepage, keywords, license) are patched in by
`scripts/prepare-wasm-publish.sh` (see next section).

### Steps

1. Build release: `wasm-pack build --target web --out-dir pkg --release`
   inside `pir-sdk-wasm/`.
2. Patch metadata:
   `./scripts/prepare-wasm-publish.sh`
   (edits `pir-sdk-wasm/pkg/package.json` in place to add
   `repository`, `homepage`, `keywords`, `bugs`, and a tighter
   `description`).
3. Dry run: `(cd pir-sdk-wasm/pkg && npm publish --dry-run)`.
4. Publish: `(cd pir-sdk-wasm/pkg && npm publish --access public)`.
   The `--access public` is required for unscoped packages on a
   free npm account.
5. Tag the release:
   `git tag -s pir-sdk-wasm-npm-v<version> -m "..."`.

The npm version **must** match the Rust crate version. Let the
helper script's sanity-check enforce this — it reads the version
from `Cargo.toml` and refuses to proceed if `pkg/package.json` is
out of sync.

## Version bump checklist

Use this before every crate or npm release:

- [ ] `version` bumped in `Cargo.toml` (or `package.json` for npm).
- [ ] `CHANGELOG.md` Unreleased section promoted to versioned
      heading; `[Unreleased]` / `[<version>]` compare links updated.
- [ ] `cargo test` / `cargo test --features onion` clean where
      applicable.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] `cargo doc --no-deps -p <crate>` builds without warnings.
- [ ] (for `pir-sdk-wasm`) `wasm-pack build --target web` succeeds,
      `pkg/pir_sdk_wasm.d.ts` matches the public API in the README.
- [ ] (for npm release) `scripts/prepare-wasm-publish.sh` run; diff
      on `pkg/package.json` checked.
- [ ] `git status` clean on the release branch.

## Unpublishing

crates.io does not support unpublishing. The only remediation is
**`cargo yank`**:

```bash
cargo yank --vers <version> -p <crate>
```

A yanked version stays on the registry (dep resolvers that already
have it in a `Cargo.lock` continue to work) but is hidden from fresh
resolves. Yanking is reversible: `cargo yank --vers <version>
--undo -p <crate>`.

For npm, `npm unpublish <pkg>@<version>` works for 72 hours after
publish. Past that, use `npm deprecate` with a migration message.

## Preserving PIR invariants across releases

🔒 Every release must preserve the **Merkle INDEX item-count
symmetry** invariant and the K=75 INDEX / K_CHUNK=80 CHUNK /
25-MERKLE padding. Before tagging a release, re-read the
"CRITICAL SECURITY REQUIREMENTS" section of the root `CLAUDE.md`
and confirm that no change in the release window has touched:

- `pir-sdk-client::dpf::query_batch` / `harmony::query_single` /
  `onion::query_index_level` symmetric-probe paths.
- `pir-sdk-client::merkle_verify::verify_bucket_merkle_batch_generic`
  K-padded sibling-batch driver.
- `pir-sdk-client::onion_merkle::verify_onion_merkle_batch`
  K-padded FHE sibling-batch driver.
- `pir-sdk-wasm::client::WasmDpfClient` /
  `WasmHarmonyClient::sync` / `query_batch` — they're thin shims;
  a change in the native client does not reach through them, but a
  change in the WASM layer can bypass them.

If any of those files appear in `git log --oneline v<prev>..HEAD`,
make a note in the release PR explaining how the invariants are
preserved.
