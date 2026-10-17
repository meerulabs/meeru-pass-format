#!/usr/bin/env python3
"""Decrypts a Meeru Pass vault with nothing but the master password and the Secret Key.

An independent implementation of FORMAT.md: it reads the vault from a backup file or straight
from Sui (through any Sui GraphQL endpoint), and needs no Meeru software or service.

    pip install pynacl argon2-cffi
    python meeru_decrypt.py --vault 0x… --network mainnet --out my-vault
    python meeru_decrypt.py --backup vault-backup.json --out my-vault

The Secret Key and master password are asked for (or read from MEERU_SECRET_KEY and
MEERU_PASSWORD). Output: `items.json` with every item in plain text, and attachments under `files/`.
Treat that folder like the passwords themselves.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.request

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.exceptions import CryptoError

NETWORKS = {
    "mainnet": {
        "graphql": "https://graphql.mainnet.sui.io/graphql",
        "file_stores": "0xe90800b9c468a1e34fdf50cb5d71760821e0af559b8bc155b81722d6f718f22a",
    },
    "testnet": {
        "graphql": "https://graphql.testnet.sui.io/graphql",
        "file_stores": "0x8e584cecf26231acbb208da6219d25fcd8e0c7275034743871c9b48ff828f4d5",
    },
}

NONCE, TAG = 24, 16
CHUNK_PLAINTEXT = 15000 - NONCE - TAG
DEVICE_NAME_KIND = {"other": "suipass_device"}


class Failure(Exception):
    pass


# ---- 1. Secret Key -------------------------------------------------------------------

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
FORMATS = (("SP2", 32, 2), ("SP1", 16, 1))


def parse_secret_key(text):
    cleaned = "".join(c for c in text.upper() if c.isascii() and c.isalnum()).translate(str.maketrans("OIL", "011"))
    for prefix, key_bytes, check_bytes in FORMATS:
        if cleaned.startswith(prefix):
            body = cleaned[len(prefix):]
            break
    else:
        raise Failure("that isn't a Secret Key (it starts with SP2- or SP1-)")
    out, buffer, bits = bytearray(), 0, 0
    for symbol in body:
        value = ALPHABET.find(symbol)
        if value < 0:
            raise Failure("the Secret Key has a character that can't be in one")
        buffer, bits = (buffer << 5) | value, bits + 5
        if bits >= 8:
            bits -= 8
            out.append((buffer >> bits) & 0xFF)
            buffer &= (1 << bits) - 1
    if len(out) != key_bytes + check_bytes:
        raise Failure("the Secret Key is too short or too long")
    key, check = bytes(out[:key_bytes]), bytes(out[key_bytes:])
    if hashlib.sha256(b"suipass-secret-key" + key).digest()[:check_bytes] != check:
        raise Failure("the Secret Key has a typo (its checksum doesn't match)")
    return key


# ---- 2. Primitives -------------------------------------------------------------------

def hkdf(ikm, info, length=32, salt=None):
    prk = hmac.new(salt if salt is not None else bytes(32), ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out, counter = out + block, counter + 1
    return out[:length]


def aead_open(key, aad, sealed):
    if len(sealed) < NONCE + TAG:
        raise CryptoError("too short")
    return crypto_aead_xchacha20poly1305_ietf_decrypt(sealed[NONCE:], aad, sealed[:NONCE], key)


# ---- 3. Header -----------------------------------------------------------------------

def vault_key(header_bytes, password, secret_key):
    header = json.loads(header_bytes)
    if header.get("version") != 1:
        raise Failure(f"unknown header version {header.get('version')}")
    kdf, salt = header["kdf"], base64.b64decode(header["salt"])
    if len(salt) != 16 or kdf["memory_kib"] < 19456 or kdf["iterations"] < 2 or not 1 <= kdf["parallelism"] <= 8:
        raise Failure("the header's key derivation settings are invalid or too weak")
    fingerprint = hkdf(secret_key, b"suipass-secret-key-fingerprint", 4).hex()
    if fingerprint != header["secret_key_fingerprint"]:
        raise Failure("this Secret Key belongs to another vault")
    from_password = hash_secret_raw(password.encode(), salt, time_cost=kdf["iterations"], memory_cost=kdf["memory_kib"],
                                    parallelism=kdf["parallelism"], hash_len=32, type=Type.ID, version=19)
    from_secret = hkdf(secret_key, b"suipass-auk-v1", salt=salt)
    unlock = bytes(a ^ b for a, b in zip(from_password, from_secret))
    try:
        return aead_open(unlock, b"suipass-header-v1", base64.b64decode(header["wrapped_vault_key"]))
    except CryptoError:
        raise Failure("wrong master password") from None


# ---- 4, 5. Items and attachments ------------------------------------------------------

def open_item(key, vault_id, item_id, sealed):
    aad = b"suipass-item-v1\0" + vault_id.encode() + b"\0" + item_id
    return json.loads(aead_open(key, aad, sealed))


def open_file(file_ref, vault_id, chunks):
    """`chunks`: the sealed chunks in order."""
    size, file_id, key = file_ref["size"], bytes.fromhex(file_ref["id"]), bytes.fromhex(file_ref["key"])
    count = max(1, -(-size // CHUNK_PLAINTEXT))
    if len(chunks) != count:
        raise Failure(f"{file_ref['name']}: {len(chunks)} of {count} pieces found")
    out = b""
    for index, chunk in enumerate(chunks):
        aad = b"suipass-file-v1\0" + vault_id.encode() + b"\0" + file_id + index.to_bytes(4, "little") + count.to_bytes(4, "little")
        out += aead_open(key, aad, chunk)
    if len(out) != size:
        raise Failure(f"{file_ref['name']}: wrong size")
    return out


def split_blob(file_ref, blob):
    """A file's sealed chunks one after another (how devices keep them) into the chunks."""
    size, chunks, start = file_ref["size"], [], 0
    count = max(1, -(-size // CHUNK_PLAINTEXT))
    for index in range(count):
        plain = min(CHUNK_PLAINTEXT, max(0, size - index * CHUNK_PLAINTEXT))
        chunks.append(blob[start:start + plain + NONCE + TAG])
        start += plain + NONCE + TAG
    return chunks


def file_refs(item):
    """Every file an item references: its document, attachment fields and recently removed files."""
    refs = []
    if item.get("document"):
        refs.append(("", item["document"]))
    refs += [("", f["file"]) for f in item.get("fields", []) if f.get("file")]
    refs += [("removed", r["file"]) for r in item.get("removed_files", [])]
    return refs


# ---- 6. Reading Sui through GraphQL ---------------------------------------------------

class Bcs:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, n):
        piece = self.data[self.at:self.at + n]
        if len(piece) != n:
            raise Failure("unexpected data on chain")
        self.at += n
        return piece

    def uleb(self):
        value, shift = 0, 0
        while True:
            byte = self.take(1)[0]
            value |= (byte & 0x7F) << shift
            shift += 7
            if byte < 0x80:
                return value

    def u64(self):
        return int.from_bytes(self.take(8), "little")

    def bytes(self):
        return self.take(self.uleb())

    def address(self):
        return self.take(32)


class Chain:
    def __init__(self, url):
        self.url = url

    def query(self, text, variables=None):
        body = json.dumps({"query": text, "variables": variables or {}}).encode()
        request = urllib.request.Request(self.url, data=body, headers={"content-type": "application/json"})
        with urllib.request.urlopen(request, timeout=60) as response:
            answer = json.load(response)
        if answer.get("errors"):
            raise Failure(f"Sui GraphQL: {answer['errors'][0].get('message')}")
        return answer["data"]

    def contents(self, address):
        data = self.query("query($a: SuiAddress!) { object(address: $a) { asMoveObject { contents { bcs } } } }", {"a": address})
        obj = data.get("object") and data["object"].get("asMoveObject")
        if not obj:
            raise Failure(f"object {address} not found on this network")
        return base64.b64decode(obj["contents"]["bcs"])

    def dynamic_fields(self, address):
        """(name bcs, value bcs, name type) of every dynamic field, page by page."""
        cursor = None
        while True:
            data = self.query("""query($a: SuiAddress!, $after: String) { object(address: $a) { asMoveObject {
                dynamicFields(first: 50, after: $after) { pageInfo { hasNextPage endCursor }
                  nodes { name { type { repr } bcs } value { ... on MoveValue { bcs } } } } } } }""", {"a": address, "after": cursor})
            fields = data["object"]["asMoveObject"]["dynamicFields"]
            for node in fields["nodes"]:
                yield base64.b64decode(node["name"]["bcs"]), base64.b64decode(node["value"]["bcs"]), node["name"]["type"]["repr"]
            if not fields["pageInfo"]["hasNextPage"]:
                return
            cursor = fields["pageInfo"]["endCursor"]

    def table_entry(self, table, key_bcs):
        # A table's id is a UID inside another object, not an object, so ask by address.
        data = self.query("""query($a: SuiAddress!, $k: Base64!) { address(address: $a) {
            dynamicField(name: {type: "0x2::object::ID", bcs: $k}) { value { ... on MoveValue { bcs } } } } }""",
                          {"a": table, "k": base64.b64encode(key_bcs).decode()})
        field = data["address"] and data["address"]["dynamicField"]
        return base64.b64decode(field["value"]["bcs"]) if field else None


def read_chain(chain, vault_id):
    vault = Bcs(chain.contents(vault_id))
    vault.address()  # id
    vault.address()  # owner
    for _ in range(vault.uleb()):
        vault.address()  # devices
    header = vault.bytes()
    items = {}
    for name, value, kind in chain.dynamic_fields(vault_id):
        if not kind.endswith("::vault::ItemKey"):
            continue
        item_id, record = Bcs(name).bytes(), Bcs(value)
        record.u64()  # revision
        items[item_id] = record.bytes()
    return header, items


def chain_chunks(chain, vault_id, file_stores):
    """{(file id, index): sealed chunk} for every attachment of the vault."""
    stores = Bcs(chain.contents(file_stores))
    stores.address()
    table = "0x" + stores.address().hex()
    entry = chain.table_entry(table, bytes.fromhex(vault_id[2:]))
    if entry is None:
        return {}
    files = "0x" + entry.hex()
    chunks = {}
    for name, value, _ in chain.dynamic_fields(files):
        key = Bcs(name)
        file_id, index = key.bytes(), key.u64()
        chunks[(file_id.hex(), index)] = Bcs(value).bytes()
    return chunks


# ---- Output --------------------------------------------------------------------------

def safe(name):
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", name).strip(" .")
    return name or "unnamed"


def main():
    parser = argparse.ArgumentParser(description="Decrypt a Meeru Pass vault without Meeru software.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--vault", help="vault id (0x…), read from Sui")
    source.add_argument("--backup", help="a backup file written by `meeru-pass backup`")
    parser.add_argument("--network", choices=sorted(NETWORKS), default="mainnet")
    parser.add_argument("--graphql", help="another Sui GraphQL endpoint for the network")
    parser.add_argument("--out", required=True, help="folder for items.json and files/ (created; must be empty)")
    parser.add_argument("--all", action="store_true", help="also output device-name records")
    args = parser.parse_args()

    if os.path.exists(args.out) and os.listdir(args.out):
        raise Failure(f"{args.out} is not empty")
    secret_key = parse_secret_key(os.environ.get("MEERU_SECRET_KEY") or getpass.getpass("Secret Key: "))
    password = os.environ.get("MEERU_PASSWORD") or getpass.getpass("Master password: ")

    chain = None
    if args.backup:
        with open(args.backup, "rb") as f:
            backup = json.load(f)
        vault_id, header = backup["vault_id"], base64.b64decode(backup["header"])
        sealed = {bytes.fromhex(i): base64.b64decode(e["sealed"]) for i, e in backup["items"].items() if e.get("pending") != "delete"}
    else:
        vault_id = "0x" + args.vault.lower().removeprefix("0x").rjust(64, "0")
        chain = Chain(args.graphql or NETWORKS[args.network]["graphql"])
        header, sealed = read_chain(chain, vault_id)

    key = vault_key(header, password, secret_key)
    items = []
    for item_id, data in sorted(sealed.items()):
        try:
            item = open_item(key, vault_id, item_id, data)
        except CryptoError:
            raise Failure(f"item {item_id.hex()} doesn't open: it was changed or belongs to another vault") from None
        if item.get("kind") == DEVICE_NAME_KIND and not args.all:
            continue
        items.append({"id": item_id.hex(), "item": item})

    os.makedirs(args.out, exist_ok=True)
    wanted = [(entry, folder, ref) for entry in items for folder, ref in file_refs(entry["item"])]
    saved, missing = 0, []
    if wanted:
        if chain is None:
            missing = [ref["name"] for _, _, ref in wanted]
        else:
            chunks = chain_chunks(chain, vault_id, NETWORKS[args.network]["file_stores"])
            for entry, folder, ref in wanted:
                count = max(1, -(-ref["size"] // CHUNK_PLAINTEXT))
                pieces = [chunks.get((ref["id"], i)) for i in range(count)]
                if None in pieces:
                    missing.append(ref["name"])
                    continue
                directory = os.path.join(args.out, "files", f"{safe(entry['item'].get('title', ''))}-{entry['id'][:8]}", folder)
                os.makedirs(directory, exist_ok=True)
                with open(os.path.join(directory, safe(ref["name"])), "wb") as f:
                    f.write(open_file(ref, vault_id, pieces))
                saved += 1

    with open(os.path.join(args.out, "items.json"), "w", encoding="utf-8") as f:
        json.dump({"vault": vault_id, "items": items}, f, ensure_ascii=False, indent=2)
    print(f"{len(items)} items written to {os.path.join(args.out, 'items.json')}; {saved} attachments saved")
    if missing:
        where = "a backup doesn't include attachments; read the vault from Sui with --vault" if chain is None else "not on chain"
        print(f"{len(missing)} attachments not saved ({where}): {', '.join(missing)}")


if __name__ == "__main__":
    try:
        main()
    except Failure as failure:
        sys.exit(f"meeru-decrypt: {failure}")
