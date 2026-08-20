# zcash-sdk-kmp

Kotlin Multiplatform Zcash SDK for pcash, built on zkool's Rust core (`rlz`) instead of
the ECC Android SDK.

Ticket: MOBILE-738.

## Why not the ECC SDK

Two things pcash needs cannot be expressed in the ECC API:

- **Source-pool selection on send.** `proposeTransfer(account, recipient, amount, memo)`
  has nowhere to put it; the Rust side hardcodes `zip317_helper(None)`. `rlz` takes a pool
  bitmask as a first-class parameter.
- **One account for every address type.** ECC's alias model gives unified, sapling and
  transparent wallets separate databases and separate chain scans. In `rlz` one account
  holds them all, and `synchronize` takes a *list* of accounts and walks the chain once.

The API here is therefore modelled on what the wallet needs, not on `Synchronizer`. pcash's
ZEC layer is rewritten against it; its own adapter interfaces stay put.

## Targets

`android` and `jvm("desktop")` — no iOS anywhere in pcash. Both are JVM, so **one JNI
binding serves both** and no C ABI or second wrapper is needed. That is why `jvmSharedMain`
exists between `commonMain` and the two platform source sets.

Rust triples: `aarch64-linux-android` + `armv7-linux-androideabi` (matching pcash's
`abiFilters`), plus one host triple per desktop OS we ship.

## Layout

    zcash-sdk/src/commonMain      pure API — pools, balances, addresses, sync state
    zcash-sdk/src/jvmSharedMain   the single JNI binding + native library loading
    zcash-sdk/src/androidMain     System.loadLibrary
    zcash-sdk/src/desktopMain     unpack the binary from the jar, then System.load
    rust/rlz                      vendored fork of zkool's Rust core
    rust/zcash-jni                the JNI bridge, built into libzcash_sdk_kmp.so
    sample-shared                 the demo app — one Compose Multiplatform UI
    sample-android                Android entry point for the demo
    sample-desktop                desktop entry point for the demo

## Status

The Kotlin surface is in place: opening a wallet, restoring and deleting accounts, per-pool
balances, addresses, transaction history, a sync flow over `rlz`'s one-shot calls, and the
PCZT send path (prepare → plan → sign → extract → broadcast). Sapling parameters are
downloaded and verified by the Rust side on demand.

The demo app below exercises all of it on Android and desktop. What is left is rewriting
pcash's own ZEC layer against this SDK.

## Demo app

`:sample-shared` is a demo wallet built on this SDK — see
[sample-shared/README.md](sample-shared/README.md) for the full description.

It never asks for a seed phrase and never stores one: the phrase is read from
`local.properties` in the project root at build time, under the key **`zcash.words`**. Create
the file (it is git-ignored) and add:

```properties
zcash.words=twelve or twenty four words of the demo seed
zcash.birthday=2800000
# required whenever zcash.words is set — see below
zcash.dbKey=64 hex characters, e.g. from: openssl rand -hex 32
# optional, defaults to https://zec.rocks:443
zcash.serverUrl=https://zec.rocks:443
```

Without `zcash.words` the build still succeeds; the app just starts on a screen telling you
to add it.

**`zcash.dbKey` is mandatory whenever `zcash.words` is set.** The wallet database is
encrypted with SQLCipher, and the SDK takes the raw key verbatim — it derives nothing and
stores nothing — so a missing key would mean an unencrypted wallet. The build fails with an
explicit message instead of silently falling back. It must be exactly 64 hex characters
(a raw 32-byte key, not a passphrase); generate one with `openssl rand -hex 32`.

Changing or losing the key makes the existing database unopenable — there is no recovery
path. Delete `demo.db` (see the demo README) and let the app rescan from the birthday
height. A database created before encryption was introduced is plaintext and must be
deleted the same way.

Run it with:

```bash
./gradlew :sample-desktop:run
./gradlew :sample-android:installDebug -PzcashSdk.androidAbis=arm64-v8a
```

## Build

Requires JDK 21.

    JAVA_HOME=$(/usr/libexec/java_home -v 21) ./gradlew :zcash-sdk:build
