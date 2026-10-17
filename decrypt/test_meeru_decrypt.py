"""Checks this implementation against data sealed by Meeru Pass itself (testdata/, written by
`cargo run -p meeru-pass-core --example format_fixture -- tools/meeru-decrypt/testdata` in the Meeru Pass repository).

    python -m unittest test_meeru_decrypt
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

import meeru_decrypt as md

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "testdata")


def load(name, binary=False):
    with open(os.path.join(DATA, name), "rb" if binary else "r", encoding=None if binary else "utf-8") as f:
        return f.read() if binary else json.load(f)


class Decrypt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.secrets, cls.backup, cls.expected = load("secrets.json"), load("backup.json"), load("expected-items.json")
        cls.secret_key = md.parse_secret_key(cls.secrets["secret_key"])
        cls.key = md.vault_key(base64.b64decode(cls.backup["header"]), cls.secrets["password"], cls.secret_key)

    def test_every_item_opens_to_what_the_app_wrote(self):
        self.assertEqual(len(self.backup["items"]), len(self.expected))
        for item_id, entry in self.backup["items"].items():
            item = md.open_item(self.key, self.backup["vault_id"], bytes.fromhex(item_id), base64.b64decode(entry["sealed"]))
            self.assertEqual(item, self.expected[item_id])

    def test_the_attachment_opens_from_its_chunks(self):
        ref = self.secrets["attachment"]
        chunks = md.split_blob(ref, load("attachment.sealed", binary=True))
        self.assertEqual(len(chunks), 3)
        self.assertEqual(md.open_file(ref, self.backup["vault_id"], chunks), load("attachment.plain", binary=True))

    def test_chunks_out_of_order_fail(self):
        ref = self.secrets["attachment"]
        chunks = md.split_blob(ref, load("attachment.sealed", binary=True))
        with self.assertRaises(md.CryptoError):
            md.open_file(ref, self.backup["vault_id"], [chunks[1], chunks[0], chunks[2]])

    def test_secret_key_typing_slips_are_forgiven_and_typos_caught(self):
        shown = self.secrets["secret_key"]
        sloppy = shown.lower().replace("-", " ").replace("0", "o").replace("1", "l")
        self.assertEqual(md.parse_secret_key(sloppy), self.secret_key)
        # A symbol in the middle: the last one may hold only padding bits.
        broken = shown[:10] + ("A" if shown[10] != "A" else "B") + shown[11:]
        with self.assertRaises(md.Failure):
            md.parse_secret_key(broken)

    def test_wrong_password_and_wrong_secret_key_are_told_apart(self):
        header = base64.b64decode(self.backup["header"])
        with self.assertRaisesRegex(md.Failure, "wrong master password"):
            md.vault_key(header, "not it", self.secret_key)
        with self.assertRaisesRegex(md.Failure, "another vault"):
            md.vault_key(header, self.secrets["password"], bytes(32))

    def test_an_item_moved_to_another_vault_or_id_fails(self):
        item_id, entry = next(iter(self.backup["items"].items()))
        sealed = base64.b64decode(entry["sealed"])
        other_vault = "0x" + "0" * 63 + "1"
        with self.assertRaises(md.CryptoError):
            md.open_item(self.key, other_vault, bytes.fromhex(item_id), sealed)
        with self.assertRaises(md.CryptoError):
            md.open_item(self.key, self.backup["vault_id"], bytes(16), sealed)

    def test_the_command_writes_items_from_a_backup(self):
        with tempfile.TemporaryDirectory() as out:
            env = dict(os.environ, MEERU_SECRET_KEY=self.secrets["secret_key"], MEERU_PASSWORD=self.secrets["password"])
            run = subprocess.run([sys.executable, os.path.join(HERE, "meeru_decrypt.py"), "--backup", os.path.join(DATA, "backup.json"),
                                  "--out", os.path.join(out, "vault")], env=env, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("1 attachments not saved", run.stdout)
            with open(os.path.join(out, "vault", "items.json"), encoding="utf-8") as f:
                written = json.load(f)
            self.assertEqual({e["id"]: e["item"] for e in written["items"]}, self.expected)


if __name__ == "__main__":
    unittest.main()
