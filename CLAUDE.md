# sqlx-ra-tls Development Guide

## Commit Requirements

**No AI attribution in commit messages.**

Do not include `Co-Authored-By: Claude` or any other AI attribution lines in commits.
AI tools may be used to assist with development, but all commits must be authored by the
human developer. A pre-push hook enforces this — see `.git/hooks/pre-push`.

New clones must install the hook manually:
```bash
cp -f hooks/pre-push .git/hooks/pre-push
chmod +x .git/hooks/pre-push
```

All commits must be GPG-signed:
```bash
git config commit.gpgsign true
git config user.signingkey EC13425E92A56C29
```

## Test Commands

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

Live tests (require a running sidecar + dstack simulator or CVM host) are gated
behind the `live-test` feature and `#[ignore]`; run with:

```bash
TEESQL_CLUSTER_SECRET=<64-hex> \
DSTACK_SIMULATOR_ENDPOINT=http://127.0.0.1:8090 \
cargo test --features live-test -- --ignored
```

## Publish Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ] All commits GPG-signed with no AI attribution
- [ ] Version bumped in `Cargo.toml`
- [ ] `cargo publish`
