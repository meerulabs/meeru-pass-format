# Meeru Pass data format

How a [Meeru Pass](https://github.com/meerulabs) vault is stored and encrypted, and a small
independent program that decrypts one. With these, your data does not depend on Meeru Labs: if the
company and its apps disappeared, you could still read your vault straight from the Sui chain with
your master password and Secret Key.

- [`FORMAT.md`](FORMAT.md): the format, version 1. Key derivation (Argon2id and HKDF over the master
  password and the Secret Key), XChaCha20-Poly1305 with associated data, items, attachments, and
  where each piece lives on Sui.
- [`decrypt/`](decrypt/): `meeru_decrypt.py`, one Python file written from `FORMAT.md` rather than
  from the apps' code. Its tests decrypt data sealed by the apps.

## Decrypt a vault

```sh
cd decrypt
python3 -m venv venv && venv/bin/pip install -r requirements.txt

# From the chain (any Sui GraphQL endpoint; the default is the network's public one):
venv/bin/python meeru_decrypt.py --vault 0x… --network mainnet --out my-vault

# From a backup made with `meeru-pass backup` (works offline; attachments aren't in backups):
venv/bin/python meeru_decrypt.py --backup vault-backup.json --out my-vault
```

It asks for the Secret Key (on your Emergency Kit) and the master password, then writes
`my-vault/items.json` with every item in plain text, and attachments under `my-vault/files/`.
**That folder holds your secrets unencrypted**: keep it on an encrypted disk and delete it when you
are done.

Needs Python 3.9 or newer, [PyNaCl](https://pypi.org/project/PyNaCl/) (libsodium) and
[argon2-cffi](https://pypi.org/project/argon2-cffi/).

## Tests

```sh
cd decrypt && venv/bin/python -m unittest -v test_meeru_decrypt
```

`decrypt/testdata/` was sealed by Meeru Pass itself; the password and Secret Key in it are test
values. The Meeru Pass repository checks that the apps keep opening the same data.

## Status

The format and this program have not been audited yet. Found a mistake, or something the document
doesn't say clearly enough to implement it? Please open an issue.
