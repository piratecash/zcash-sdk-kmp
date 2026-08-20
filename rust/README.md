# rust

Cargo workspace holding our copy of zkool's Rust core and the JNI bridge on top of it.

## `rlz/`

Vendored from upstream zkool2 (https://github.com/hhanh00/zkool2, `rust/`), then gated
locally. Nearly every local change is additive — `#[cfg(feature = ...)]` lines,
`optional = true` dependency flags, two visibility narrowings, and the tests that pin the
`nym` guards — so a re-vendor stays a merge, not a rewrite. One change is **not** additive:
the plaintext seed write is gone, which diverges from upstream behaviour. See
[Local changes](#local-changes).

The workspace `Cargo.toml` is upstream's **root** manifest, not the crate manifest: all
13 forked git dependencies live in its `[patch.crates-io]`, and patches only apply from a
workspace root. Vendoring the crate alone does not build.

## `zcash-jni/`

The JNI bridge for `cash.p.zcash.ZcashJni`. Separate crate so the bridge itself adds no
diff to `rlz`; depends on `rlz` with `default-features = false` (no `flutter`) as an rlib
and produces `libzcash_sdk_kmp.so`.

`rlz::Sink<V>` is zkool's own streaming trait, not flutter_rust_bridge's — `StreamSink`
is merely one impl. A JNI `Sink` slots into `sync::synchronize_impl` without touching
sync internals.

## Building

### Cargo directly

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export ANDROID_NDK_HOME="$HOME/Library/Android/sdk/ndk/27.0.12077973"

cargo check -p rlz --locked                          # host
cargo ndk -t arm64-v8a   -P 27 -- build -p zcash-jni # armv8
cargo ndk -t armeabi-v7a -P 27 -- build -p zcash-jni # armv7
cargo build -p zcash-jni                             # host dylib, for desktop
```

NDK 27.0.12077973 is the version ECC ships its own Zcash Rust backend with, so it is the
one proven against this dependency stack.

### Through Gradle

`:zcash-sdk` drives cargo itself: `cargoBuildAndroid` feeds the AAR's `jni/<abi>/`,
`cargoBuildDesktop` stages the host binary as `native/<triple>/` in the desktop jar.

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
export ANDROID_HOME="$HOME/Library/Android/sdk"

./gradlew :zcash-sdk:assemble
./gradlew :zcash-sdk:cargoBuildAndroid -PzcashSdk.rustRelease=true -PzcashSdk.androidAbis=arm64-v8a
```

ABIs come from `zcashSdk.androidAbis`; the debug profile is the default because a release
build of this dependency graph takes ~4.5 min per ABI.

Upstream `rlz` declares a `cdylib` alongside the `rlib` we link, so cargo-ndk emits a
second `librlz.so` we do not need. `CargoNdkTask` drops it rather than patching `rlz`.

## Features

`default = []`. The shipped artifact — what `zcash-jni` links — turns **everything** off.

| Feature | Pulls in | On in the artifact |
| --- | --- | --- |
| `flutter` | `flutter_rust_bridge` + `voting`, `plugin`, `contacts`, `raptor`, `nym` | no |
| `voting` | `zcash_voting` | no |
| `plugin` | `rhai`, `zip` | no |
| `contacts` | `vcard4` | no |
| `raptor` | `raptorq`, `qrcode` | no |
| `nym` | `nym-smolmix`, `nym-sdk`, `nym-network-defaults`, `bincode1`, `uuid` | no |
| `ledger` / `zemu` | `hidapi`, `ledger-transport`(`-zemu`) | no |
| `graphql` | juniper/warp stack | no |

`arti-client` (Tor) stays unconditional: `Coin.transport == 1` routes the whole gRPC
channel through it, and Tor is a shipped pcash feature.

With `nym` off, transport `2` and `nym://` URLs are **rejected**, never downgraded to
clear-net — `Coin::set_transport`, `Coin::client`, and `ZebraClient::jsonrpc_impl` each
carry an explicit `bail!`, pinned by tests that assert the guard's own message.

## Local changes

`cargo check -p rlz --no-default-features` is green, as is one build per feature.

- `rlz/Cargo.toml` — `default = []`; eleven dependencies made `optional`. `httparse` stays
  unconditional: the Tor path shares it.
- `#[cfg(feature = ...)]` on the `voting` / `plugin` / `contacts` / `raptor` / `nym` modules
  and on the flutter-only bindings (`api/vault.rs`, `vault/dart.rs`, the ledger signing
  entry point, the `StreamSink` imports).
- `net::is_nym_url` + `NYM_URL_SCHEME` live ungated in `net/mod.rs`: the classification must
  exist with `nym` off, otherwise a `nym://` URL would reach tonic and connect in the clear.
- **Visibility narrowed** — `lwd::compact_tx_streamer_client` and the `GRPCClient` alias are
  `pub(crate)`. `lwd.rs` is prost-generated: regenerating it restores `pub` and reopens a
  gRPC door that bypasses `Coin::client`. Re-apply after any regeneration.

### Not additive — the plaintext seed write is gone

`store_account_seed_fingerprint` (`rlz/src/db.rs`, upstream `store_account_seed`) no longer
writes `accounts.seed` / `accounts.passphrase`: the SDK is handed key material, it never
stores the mnemonic. The column is nullable, so every account `new_account` creates reads
back as `NULL` and `account::get_account_seed` returns `None`.

This is a behavioural change, not a `cfg` line, and it breaks upstream code that assumes the
column is populated. None of that code is reachable here — `zcash-jni` takes `rlz` with
`default-features = false` and references neither `frost`, `io`, `voting`, `issuance` nor
`print_keys`; our only reader of the row is `list_accounts`, whose `AccountDto` drops both
columns. In upstream's Flutter build it breaks, worst first:

- `frost::protocol::get_coordinator_broadcast_account` — a `loop` that resolves the account by
  `WHERE seed = ?1` and creates it on a miss, with no retry counter. Its exit condition is now
  unreachable: it creates `frost-broadcast` accounts until the disk fills.
- `io::export_account` — backups carry `seed: None`, so restoring one yields a watch-only
  account. Silent, and only noticed at restore time.
- `frost::protocol::get_mailbox_account` — panics at `.expect("Seed should be set")` on first
  use, from FROST signing as well as DKG; `frost::dkg::dkg_finalize` panics the same way.
- `api::account::print_keys` — panics on `seed.unwrap()`.
- `api::account::get_account_seed` (frb), `api::issuance`, `voting` — degrade to `None` or an
  `anyhow` error.

`io.rs` still writes `seed` on the import path, so the no-plaintext-seed property holds
because that path is unreachable from JNI, not because the column cannot be written.

On re-vendor this hunk is a **decision** — our property or upstream FROST/backup — never an
automatic merge. Gating the seed-dependent modules behind `flutter`, the way `voting` and
friends already are, would turn the conflict into a compile-time fact; follow-up, not done.

### Not additive — spending keys are no longer stored

The DB keeps viewing keys only. `plan::sign_transaction` takes the unified spending key as its
last argument (`UnifiedSpendingKey::from_bytes(Era::Orchard, …)`), checks it derives the
account's own viewing keys, and uses it; the three writers `store_account_transparent_sk`,
`store_account_sapling_sk` and `store_account_orchard_sk` are gone, the transparent address
writers store `NULL` where they stored `sk`, and `db::scrub_spending_keys` NULLs the four legacy
secret columns on every open. `api::pay::sign_transaction_with_key` is the only entry point that
accepts a key; the seven upstream call sites that had no key to pass — `api::pay`, `migrate`
(twice), `frost::protocol`, `api::issuance`, `graphql::query`, `graphql::mutation` — pass
`plan::NO_SPENDING_KEY`, which fails the parse and returns an error instead of signing. To reach
JNI the key derivation was widened: `api::coin::network_from_coin` was extracted out of
`Coin::network`, and `api::key::derive_spending_key` is `pub` without an frb attribute.

`can_sign` changed meaning: it is now "the account has a `seed_fingerprint`", i.e. the app can
re-derive the key, not "a key sits in the DB". The `None =>` branch of transparent input signing
is gone with it — the key is mandatory. Imports from WIF, tprv, Sapling xsk and UFVK, and
Ledger restore, are watch-only and report `can_sign = false`, as before.

Consequences, worst first:

- Accounts created by the removed Kotlin `ZcashWallet.createAccount` are permanently unspendable
  after the scrub: the mnemonic was generated inside Rust and never handed out, yet in the DB
  such an account is indistinguishable from one restored from a mnemonic. At the time of the
  change the class is empty — the repository has no `createAccount` call sites.
- `io::import_account` (`io.rs:578-606`) still writes `xsk`/`sk` with raw SQL, bypassing the
  deleted writers, but the scrub runs on every open, so a restored backup is effectively
  watch-only. It also restores `seed_fingerprint` as-is (`io.rs:555`), so a pre-reform backup
  reports `can_sign = true` while signing can never succeed. Unreachable from JNI, and
  fail-closed: the flutter paths pass `NO_SPENDING_KEY`.
- In flutter builds `create_account` from a mnemonic writes `seed_fingerprint` while the frb
  `sign_transaction` passes `NO_SPENDING_KEY`: same class as the backup case — `can_sign` says
  `true`, the signature always fails. Not reachable from the shipped artifact (`default = []`).
- `rlz/tests/zsa_transfer_test.rs` (ignored, live-network) still compiles — `api::pay::sign_transaction`
  keeps its two-argument signature — but now fails at `.expect("sign")`, because that wrapper passes
  `NO_SPENDING_KEY`. A deliberate fork divergence, not a build regression.

On re-vendor this hunk is a **decision** — our property or upstream's in-DB spending keys —
never an automatic merge.

## Binary size

Release, arm64-v8a, `default = []`: **11.6 MB** (11,573,912 bytes) — down from **71.7 MB**
with `default = ["flutter"]`, and below the **39.9 MB** ECC backend we ship today.

The 60 MB came almost entirely from the feature closure: the nym mixnet stack, `rhai`
(embedded scripting), `raptorq`, and `zcash_voting`. What remains unconditional is
`frost-rerandomized`, `rayon`, `reqwest`, and the Tor stack.
