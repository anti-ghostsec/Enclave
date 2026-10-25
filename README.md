# Enclave

An encrypted file vault for Android. No ads, no internet permission, no analytics.

## Features
- **Encrypted vault** for any files: folders, move, multi-select, search, sort, a grid or list view with encrypted thumbnails, and a duplicate finder.
- **Built-in viewer**: swipe through photos, GIFs, videos and audio. It has pinch zoom, a slideshow and a delete button. Videos start muted and loop. Playback reads straight from the encrypted file.
- **Safer sharing**: Enclave's own share list shows apps only, never people or recent chats. You can limit it to apps you choose and confirm before anything is sent. Shared links end when the screen turns off, or after 30 minutes.
- **Other apps can pick from Enclave** (opt-in): browsers and chats can attach a vault file directly.
- **Password plus an optional keyfile**, **duress passwords** (decoy vault or silent wipe), wipe after N wrong attempts, and exponential lock-out. A decoy opened on its own is read-only, so it can never write over the hidden real vault. You fill it from Settings while the real vault is open.
- **Disguise** (off by default): a preset name and icon, a working calculator front, or a custom home-screen icon.
- Locks when the screen turns off or Enclave is left. Screenshots, recent-apps previews and audio capture are blocked.
- A built-in folder browser for import, export and keyfiles. It works inside profiles where the system file picker doesn't, such as Motorola Secure Folder, and shows photo and video previews that are made in memory and never saved.

## Security model

| Layer | What it does |
|---|---|
| Argon2id (64 MiB, 3 passes) | Turns the password (plus the SHA-512 of the keyfile, used as Argon2's secret) into a 256-bit key-encryption key. |
| Header key slots | 4 slots, each holding the master key wrapped with AES-256-GCM. Unused slots are random bytes, so the number of passwords, and which one is a duress password, can't be told apart. |
| Hardware key | The header is sealed by a non-exportable AES-256 key in StrongBox or the TEE, so copied app data can't be brute-forced off the device. Deleting this key crypto-shreds the vault. |
| Files | Each file has its own random 256-bit key and is encrypted with chunked AES-256-GCM. The chunk index and a final-chunk flag are in the AAD, which stops chunks being reordered or the file truncated. Names and folders live in an encrypted index. |
| Deniable containers | Everything lives in equal-sized 4 GiB containers of random-looking bytes ([`native/deniable`](native/deniable)). Each vault is volumes inside them, scattered in 4 KiB blocks encrypted with XChaCha20-Poly1305 and opened by a key derived from the vault's master key. Without a key, nothing says how many vaults there are, how many files, how big they are or when they were written. When space runs low, another container is added, so a vault grows without limit and without copying anything. |
| Crash safety | New data only ever goes into space nothing saved still uses. The other containers are flushed first, then the root (index, settings and where every file lives) and the home container, which the crate saves atomically. A power cut leaves the previous state intact. |

**Quantum resistance:** Enclave uses only 256-bit symmetric cryptography (AES-256, SHA-2 and Argon2id), with no RSA or ECC anywhere.

### Known limits
- Enclave hasn't been audited by an independent security firm. If being found out could put you in danger, don't rely on it alone.
- A backup of the raw vault only works on the same phone, because it's bound to that phone's hardware key. Uninstalling Enclave or resetting the phone destroys the vault.
- The containers' total size is visible: it's a rough upper bound on how much is stored.
- A decoy made before containers keeps its own directory, which shows a second vault exists. Remove it and add a new decoy to move it inside the containers.
- On flash storage the controller can keep old copies of blocks that no app can reach.
- "Open with" and "Share" give the decrypted bytes to the receiving app, which could keep a copy. Exported files are plaintext.
- Passwords typed into the UI pass through immutable strings that can't be wiped from memory.
- The folder browser needs Android's "All files access" permission.

## Upgrading from earlier versions
Vaults in the original one-directory format move into the containers on their first unlock after updating. Every encrypted file, preview, the index and the settings are copied byte for byte, nothing is decrypted, and each copy is checked against its original with SHA-256. Only once the move is marked complete is the old directory removed. If it's interrupted, the old vault is untouched and the next unlock carries on.

## Build
Needs the Android NDK (r29) and Rust with the `aarch64-linux-android` target. Gradle builds the Rust code itself.
```
./gradlew assembleDebug                       # app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest                   # file-format and upgrade tests, run on the PC
./gradlew assembleRelease                     # signed if the properties below are set
```
Release signing is read from your user-level `~/.gradle/gradle.properties`, never from this repository:
```
ENCLAVE_STORE_FILE=/path/to/release.jks
ENCLAVE_STORE_PASSWORD=...
ENCLAVE_KEY_ALIAS=...
ENCLAVE_KEY_PASSWORD=...
```
