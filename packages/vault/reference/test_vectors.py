"""Run the shared vector catalog with: python -B packages/vault/reference/test_vectors.py."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import unittest

from reader import FRAME, InvalidVault, plaintext, records, unlock, vault_metadata, verify_segment

VECTORS = Path(__file__).resolve().parents[1] / "codec" / "test" / "vectors"
CASES = json.loads((VECTORS / "cases.json").read_bytes())


def asset(name):
    stored = (VECTORS / name).read_bytes()
    return base64.b64decode(stored, validate=True) if name.endswith(".b64") else stored


def record_bytes(case):
    raw = asset(case["asset"])
    if "prefix" in case:
        start, end = case["slice"]
        frame = raw[start:end] + (asset(case["tag"]) if "tag" in case else b"")
        return asset(case["prefix"]) + frame * case.get("repeat", 1)
    if case.get("swap_frames"):
        split = 69 + FRAME + 20
        return raw[:69] + raw[split:] + raw[69:split]
    return raw


class Vectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vault_id, cls.public_key = vault_metadata(asset("VAULT.json"))
        cls.key_for_id = staticmethod(unlock(asset(CASES["keyring"]), cls.vault_id, passphrase=CASES["passphrase"]))

    def expect(self, case, operation):
        if "error" in case:
            with self.assertRaisesRegex(InvalidVault, "^" + case["error"] + "$"):
                operation()
            return None
        return operation()

    def test_record_vectors(self):
        for case in CASES["record_cases"]:
            with self.subTest(case=case["name"]):
                def decode():
                    parsed = list(records(record_bytes(case)))
                    if len(parsed) != 1:
                        raise InvalidVault("LENGTH")
                    if case.get("scan_only"):
                        return None
                    key = (lambda _: bytes(32)) if case.get("wrong_key") else self.key_for_id
                    return parsed[0], plaintext(parsed[0], case.get("vault_id", self.vault_id), key)

                result = self.expect(case, decode)
                if result is not None:
                    (kind, seq, key_id, *_), raw = result
                    self.assertEqual((kind, seq, len(raw)), (case["type"], case["sequence"], case["length"]))
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), case["sha256"])
                    if "blob_id" in case:
                        key = self.key_for_id(key_id, identity=True)
                        self.assertEqual(hmac.digest(key, raw, "sha256").hex(), case["blob_id"])

    def test_metadata_vectors(self):
        for case in CASES["metadata_cases"]:
            with self.subTest(case=case["name"]):
                result = self.expect(case, lambda: vault_metadata(asset(case["asset"])))
                if result is not None:
                    self.assertEqual(result, (CASES["metadata"]["vault_id"],
                                              base64.b64decode(CASES["metadata"]["signing_public_key"])))

    def test_manifest_vectors(self):
        positions = {}
        for case in CASES["manifest_cases"]:
            with self.subTest(case=case["name"]):
                args = (asset(case["asset"]), asset(case["signature"]), self.public_key, self.vault_id,
                        {name: asset(path) for name, path in case["files"].items()})
                prior = {"previous": positions[case["prior"]]} if "prior" in case else {}
                result = self.expect(case, lambda: verify_segment(*args, **prior))
                if result is not None:
                    positions[case["name"]] = result[0]
                    _, decoded = verify_segment(*args, **prior, key_for_id=self.key_for_id)
                    self.assertEqual([hashlib.sha256(raw).hexdigest() for raw in decoded], case["plaintext_sha256"])

    def test_keyring_vectors(self):
        expected = self.key_for_id(CASES["ids"]["collection"])
        for case in CASES["keyring_cases"]:
            with self.subTest(case=case["name"]):
                if case.get("recovery"):
                    credential = {"recovery_key": bytes.fromhex(CASES["recovery_key"])}
                else:
                    passphrase = CASES["changed_passphrase"] if case.get("changed_passphrase") else CASES["passphrase"]
                    credential = {"passphrase": "TEST ONLY wrong" if case.get("wrong_passphrase") else passphrase}
                result = self.expect(case, lambda: unlock(asset(case["asset"]), case.get("vault_id", self.vault_id),
                                                           **credential))
                if result is not None:
                    self.assertEqual(result(CASES["ids"]["collection"]), expected)

    def test_reader_line_limit(self):
        self.assertLess(len(Path(__file__).with_name("reader.py").read_bytes().splitlines()), 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
