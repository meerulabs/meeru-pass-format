# Meeru Pass data format

Version 1. This document is enough to decrypt a Meeru Pass vault without any Meeru software or
service: read the ciphertext from Sui (any fullnode or indexer) or from a backup file, and open it
with the master password and the Secret Key. [`decrypt/`](decrypt/) is an independent implementation
of it, written from this document.

Everything below is fixed for existing vaults. The domain strings start with `suipass-` because
that was the product's first name; they never change.

## 1. Secrets the user holds

- **Master password**: any string, used as its UTF-8 bytes.
- **Secret Key**: random bytes shown as Crockford base32 with a checksum.

| Prefix | Key bytes | Checksum bytes | Shown as |
|---|---|---|---|
| `SP2` (current) | 32 | 2 | `SP2-` + eleven groups of five symbols |
| `SP1` (first vaults) | 16 | 1 | `SP1-` + four groups of seven symbols |

Parsing: keep only ASCII letters and digits, uppercase them, read `O` as `0` and `I`/`L` as `1`,
strip the prefix, then read 5 bits per symbol from the alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`,
most significant bit first, emitting a byte every 8 bits and dropping the leftover bits. The result
must be exactly key bytes + checksum bytes long, and the checksum must equal the first checksum
bytes of `SHA-256("suipass-secret-key" || key)`.

Fingerprint (stored in the header, not secret): `hex(HKDF-SHA256(salt = none, ikm = key,
info = "suipass-secret-key-fingerprint", 4 bytes))`. It lets software tell a wrong Secret Key from
a wrong password.

## 2. Primitives

- **HKDF**: HKDF-SHA256 (RFC 5869). "Salt none" means the RFC default (32 zero bytes).
- **Argon2id**: version 0x13, output 32 bytes, parameters from the header.
- **AEAD**: XChaCha20-Poly1305 (24-byte nonce, 16-byte tag). A sealed value is
  `nonce (24) || ciphertext || tag (16)`; the nonce is random.

## 3. Vault header

The header is UTF-8 JSON:

```json
{
  "version": 1,
  "kdf": {"memory_kib": 65536, "iterations": 3, "parallelism": 1},
  "salt": "<base64, 16 bytes>",
  "secret_key_fingerprint": "bd1b0844",
  "wrapped_vault_key": "<base64, sealed 32-byte vault key>"
}
```

Base64 is the standard alphabet with padding. Reject `version` other than 1, a salt that isn't 16
bytes, and weak parameters (`memory_kib < 19456`, `iterations < 2`, `parallelism` 0 or above 8):
a tampered header must not make brute force cheap.

**Account unlock key (AUK)**:

```
from_password = Argon2id(password, salt, memory_kib, iterations, parallelism)   # 32 bytes
from_secret   = HKDF(salt = salt, ikm = secret_key, info = "suipass-auk-v1")    # 32 bytes
AUK           = from_password XOR from_secret
```

**Vault key** = AEAD-open(key = AUK, aad = `"suipass-header-v1"`, `wrapped_vault_key`). A wrong
password (with the right Secret Key) fails here.

A password change writes a new header (new salt, new wrapping); the vault key, and so every item,
stays the same.

## 4. Items

Each item has a random 16-byte id. Its sealed bytes are AEAD-sealed with the vault key and

```
aad = "suipass-item-v1" || 0x00 || vault_id || 0x00 || item_id (16 raw bytes)
```

where `vault_id` is the vault's object id as ASCII: `0x` and 64 lowercase hex digits. The
plaintext is UTF-8 JSON (at most 14,960 bytes):

| Field | Type | Notes |
|---|---|---|
| `kind` | string or object | `"login"`, `"password"`, `"secure_note"`, `"credit_card"`, `"identity"`, or `{"other": "<kind>"}` (e.g. `ssh_key`, `crypto_wallet`) |
| `title` | string | |
| `username`, `password`, `notes` | string | omitted when empty |
| `urls`, `tags` | array of strings | omitted when empty |
| `totp` | string | an `otpauth://totp/...` URI |
| `fields` | array of field | see below |
| `password_history` | array of `{password, changed_at}` | |
| `favorite`, `archived` | bool | |
| `created_at`, `updated_at`, `trashed_at` | integer | Unix seconds; `trashed_at` set while in Recently Deleted |
| `conflict_copy` | bool | |
| `document` | file reference | a Document item's file |
| `removed_files` | array of `{file, section, document, removed_at}` | removed attachments kept 30 days |
| `guarded` | bool | showing or copying its secrets asks for Touch ID or the master password first |
| `guard_declined` | bool | the user turned down guarding it |

A field is `{label, value, concealed, section, file}`; `file` is present for an attachment. Readers
must ignore fields they don't know. Items with `kind` `{"other": "suipass_device"}` are not user
data: they record a paired device's name (title) and address (username).

## 5. Attachments

A file reference is `{id, name, size, mime, key}`: `id` 16 bytes and `key` 32 bytes, both as hex.
The file is cut into chunks of 14,960 plaintext bytes (the last one shorter; an empty file is one
empty chunk), so `count = max(1, ceil(size / 14960))`. Chunk `i` is AEAD-sealed with the file's own
key and

```
aad = "suipass-file-v1" || 0x00 || vault_id || 0x00 || file_id (16 bytes)
      || u32_le(i) || u32_le(count)
```

Concatenating the opened chunks in order gives the file; its length must be `size`.

## 6. On Sui

Network packages (the original id names the types; later versions add functions):

| Network | Package (original id) | `FileStores` |
|---|---|---|
| Mainnet | `0x1e8f75487cc37e1a6dbfa3fed6d55187761e5de88fbf71432278cd6afbe09eb4` | `0xe90800b9c468a1e34fdf50cb5d71760821e0af559b8bc155b81722d6f718f22a` |
| Testnet | `0xb3ab2452df0683499f635cd1565826d90766bb4231013e1dde3d0808bfaada2d` | `0x8e584cecf26231acbb208da6219d25fcd8e0c7275034743871c9b48ff828f4d5` |

**Vault** (shared object, type `<package>::vault::Vault`), BCS:

```
id: address (32) | owner: address (32) | devices: vector<address> | header: vector<u8>
| header_revision: u64 | revision: u64 | item_count: u64
```

`header` is the JSON of section 3. (`owner` equals the vault's own id once the vault is sealed; the
real owner is then kept elsewhere. Decrypting doesn't need it.)

**Items** are the vault's dynamic fields: name `ItemKey { id: vector<u8> }` (the 16-byte item id),
value `Item { revision: u64, data: vector<u8> }`, where `data` is the sealed item of section 4.

**Attachments**: `FileStores` holds a `Table<ID, ID>` (`{id, table: {id, size}}`) from vault id to
that vault's `VaultFiles` object. The chunks are `VaultFiles`' dynamic fields: name
`ChunkKey { file: vector<u8>, index: u64 }`, value `vector<u8>` (the sealed chunk). A vault that
never attached a file has no `VaultFiles`.

BCS: `vector<T>` is a ULEB128 length and the elements; integers are little-endian; `address` is
32 raw bytes.

## 7. Backup file

`meeru-pass backup` writes the device's encrypted copy as UTF-8 JSON:

```json
{
  "format": 1,
  "vault_id": "0x…",
  "header": "<base64 of the header JSON>",
  "header_revision": 1,
  "synced_revision": 54,
  "items": {"<item id, 32 hex>": {"revision": 54, "sealed": "<base64>", "pending": "put"}}
}
```

`pending` (`put` or `delete`) marks a change not yet on chain. Attachments are not in the backup;
the device keeps them as sealed chunks in its own folder, and the chain has them too.

## 8. Not covered

The owner-recovery key and signed owner actions (`suipass-recovery-v1`, `suipass-owner-v1`), the
per-device key wrapping (`suipass-device-v1`) and Touch ID unlock only control who may write or
unlock on one device. None of them is needed to read a vault.
