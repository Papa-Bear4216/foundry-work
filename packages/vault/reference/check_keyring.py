"""Cross-check synthetic keyrings piped in from the Node lifecycle test."""
import base64
import json
import sys

from reader import unlock


def main():
    fixture = json.load(sys.stdin.buffer)
    ring = base64.b64decode(fixture["keyring"])
    vault_id = fixture["vaultId"]
    by_passphrase = unlock(ring, vault_id, passphrase=fixture["passphrase"])
    by_recovery = unlock(ring, vault_id, recovery_key=bytes.fromhex(fixture["recovery"]))
    keys = [by_passphrase(key_id) for key_id in fixture["collectionIds"]]
    assert keys == [by_recovery(key_id) for key_id in fixture["collectionIds"]]
    print(json.dumps([key.hex() for key in keys]))


if __name__ == "__main__":
    main()
