# Zcash SDK demo

A demo harness for `:zcash-sdk`: it restores a wallet from a seed phrase, syncs against
mainnet, shows per-pool balances, transaction history and receive addresses, and can send
ZEC. One shared Compose Multiplatform UI for both targets — Android and desktop.

## Setup

The seed phrase is never stored in the repository and is never typed into the app: it is
read from `local.properties` in the project root at build time and baked into a generated
`DemoConfig` (`sample-shared/build/generated/demo`; `build/` is already in `.gitignore`).

```properties
zcash.words=twelve or twenty four words of the demo seed
zcash.birthday=2800000
# required whenever zcash.words is set — see below
zcash.dbKey=64 hex characters, e.g. from: openssl rand -hex 32
# optional, defaults to https://zec.rocks:443
zcash.serverUrl=https://zec.rocks:443
```

Without `local.properties`, or without the `zcash.words` key, the build still succeeds — the
app starts and shows a screen with the instructions.

`zcash.dbKey` is **mandatory** as soon as `zcash.words` is set: the database is encrypted
with SQLCipher and the SDK takes the raw key as-is, deriving nothing, so leaving it out
would open the wallet unencrypted. The build fails with an explicit message rather than
falling back. The value is a raw 32-byte key written as 64 hex characters — not a
passphrase — so generate it with `openssl rand -hex 32`.

`zcash.birthday` is the block height the scan starts from. Zero means scanning from genesis
and takes hours; use a height close to the moment the wallet was created.

## Running

```bash
# Android (needs ANDROID_NDK_HOME, or ANDROID_HOME with the NDK installed)
./gradlew :sample-android:installDebug -PzcashSdk.androidAbis=arm64-v8a

# Desktop
./gradlew :sample-desktop:run
```

`-PzcashSdk.androidAbis` is optional: the ABI list is already set in `gradle.properties`.
Pass it to build the Rust bridge for a single architecture instead of waiting for both.

## Sending

"Review" builds the package and shows the plan: inputs, outputs and the fee. Exactly what
the plan shows is what gets sent — editing the address or the amount discards the prepared
package.

A sent transaction does not show up in the list immediately: rlz writes it into the local
history and the transactions screen reads already-written rows, so run a sync after sending.

## Clearing the data

The database is encrypted with `zcash.dbKey`, so changing that key — or carrying over a
plaintext `demo.db` from before encryption — leaves a file the app cannot open. Delete it
and let the app rescan from the birthday height; there is no recovery path.

The wallet lives in `demo.db` inside the app data directory:

- Android — `filesDir`; the easiest way is Settings → Apps → Zcash SDK demo → Clear data,
  or `adb shell pm clear cash.p.zcash.demo`;
- desktop — `~/.zcash-sdk-demo`, delete the whole directory.

The "Reset" button on the balance screen does the same for the account without touching the
database file: it deletes the account with its entire scan history and restores it from the
same seed phrase.
