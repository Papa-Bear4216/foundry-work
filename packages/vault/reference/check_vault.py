"""Cross-check a synthetic writer fixture with the independent v1 reader."""
import json
from pathlib import Path
import sys

from reader import unlock, vault_metadata, verify_segment


def main():
    root = Path(sys.argv[1])
    vault_id, public_key = vault_metadata((root / "VAULT.json").read_bytes())
    recovery_key = bytes.fromhex(sys.stdin.read())
    key_for_id = unlock((root / "keyring" / "keyring.json").read_bytes(), vault_id, recovery_key=recovery_key)
    position, decoded = (0, "0" * 64, 0), []
    for directory in sorted((root / "segments").iterdir(), key=lambda path: int(path.name)):
        entries = {file.name: file.read_bytes() for file in directory.iterdir()}
        manifest, signature = entries.pop("MANIFEST.json"), entries.pop("MANIFEST.sig")
        position, records = verify_segment(manifest, signature, public_key, vault_id, entries, position, key_for_id)
        decoded.extend(record.hex() for record in records)
    head = json.loads((root / "HEAD.json").read_bytes())
    assert head == {"segment": position[0], "manifest_sha256": position[1]}
    print(json.dumps({"position": position, "records": decoded}))


if __name__ == "__main__":
    main()
