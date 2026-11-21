"""V1 vault reader. Read wire bytes using Architecture sections 4 and 5."""
import base64
import hashlib
import hmac
import json
import re
from datetime import datetime
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
FRAME, SAFE, RING = 1 << 20, (1 << 53) - 1, "foundry-keyring/1"
class InvalidVault(ValueError): pass
def check(condition, code="SCHEMA"):
    if not condition: raise InvalidVault(code)
def canonical(value):
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return b"{" + b",".join(canonical(k) + b":" + canonical(value[k]) for k in keys) + b"}"
    if isinstance(value, list): return b"[" + b",".join(map(canonical, value)) + b"]"
    check(value is None or type(value) in (bool, str) or type(value) is int and abs(value) <= SAFE)
    return json.dumps(value, ensure_ascii=False).encode()
def document(raw, version, fields):
    try:
        value = json.loads(raw.decode())
        check(canonical(value) == raw, "CANONICAL")
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise InvalidVault("CANONICAL") from error
    check(type(value) is dict and "format" in value)
    check(value["format"] == version, "VERSION")
    shape(value, "format " + fields)
    return value
def shape(value, fields):
    check(type(value) is dict and set(value) == set(fields.split()))
def matches(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None
def integer(value, low=1):
    return type(value) is int and low <= value <= SAFE
def date(value):
    check(matches(value, r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"))
    try: datetime.fromisoformat(value)
    except ValueError: raise InvalidVault("SCHEMA")
def b64(value, size=None):
    check(isinstance(value, str))
    try: raw = base64.b64decode(value, validate=True)
    except ValueError: raise InvalidVault("SCHEMA")
    check(base64.b64encode(raw).decode() == value and (size is None or len(raw) == size))
    return raw
def derive(key, label, salt):
    check(len(key) == 32, "KEY")
    return hmac.digest(hmac.digest(salt, key, "sha256"), f"foundry/{label}/v1\x01".encode(), "sha256")
def decrypt(key, nonce, sealed, aad):
    try: return AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag: raise InvalidVault("AUTH")

def unlock(raw, vault_id, *, passphrase=None, recovery_key=None):
    ring = document(raw, RING, "vault_id version kdf master keys mac")
    check(matches(ring["vault_id"], "[0-9a-f]{32}") and integer(ring["version"]))
    check(ring["vault_id"] == vault_id, "KEY")
    kdf, master, entries = ring["kdf"], ring["master"], ring["keys"]
    shape(kdf, "name N r p salt")
    check((kdf["name"], kdf["N"], kdf["r"]) == ("scrypt", 131072, 8)
          and type(kdf["p"]) is int and kdf["p"] in (1, 2), "KDF")
    salt = b64(kdf["salt"], 32)
    shape(master, "by_passphrase by_recovery")
    wraps = {slot: b64(master["by_" + slot], 60) for slot in ("passphrase", "recovery")}
    mac = b64(ring.pop("mac"), 32)
    check(isinstance(entries, list))
    index, previous = {}, ""
    for entry in entries:
        check(type(entry) is dict)
        key_id, kind, parent, state = (entry.get(k) for k in ("key_id", "kind", "parent", "state"))
        check(matches(key_id, "[0-9a-f]{32}") and key_id > previous)
        check(kind in ("profile", "collection", "index", "signing"))
        check(matches(parent, "[0-9a-f]{32}") if kind == "collection" else parent == "master")
        fields = "key_id kind parent state wrapped "
        if state == "active":
            shape(entry, fields + ("created_at label_enc" if kind == "profile" else "created_at"))
            date(entry["created_at"])
            b64(entry["wrapped"], 60)
            check(kind != "profile" or len(b64(entry["label_enc"])) >= 29)
        else:
            shape(entry, fields + "destroyed_at")
            check(state == "destroyed" and entry["wrapped"] is None)
            date(entry["destroyed_at"])
        index[key_id], previous = entry, key_id
    for entry in entries:
        if entry["kind"] == "collection":
            parent = index.get(entry["parent"], {})
            check(parent.get("kind") == "profile" and
                  (entry["state"] == "destroyed" or parent["state"] == "active"), "KEY")
    def vk(key, label):
        return derive(key, label, bytes.fromhex(vault_id))
    def unwrap(key, blob, key_id, kind, parent, params=None):
        return decrypt(key, blob[:12], blob[12:], canonical([RING, vault_id, key_id, kind, parent, params]))
    check((passphrase is None) != (recovery_key is None), "KEY")
    slot = "passphrase" if passphrase is not None else "recovery"
    kek = (hashlib.scrypt(passphrase.encode(), salt=salt, n=131072, r=8, p=kdf["p"], dklen=32, maxmem=256 << 20)
           if passphrase is not None else vk(recovery_key, "recovery-wrap"))
    mk = unwrap(kek, wraps[slot], "master", "master", slot, kdf if slot == "passphrase" else None)
    check(hmac.compare_digest(mac, hmac.digest(vk(mk, "keyring-mac"), canonical(ring), "sha256")), "MAC")
    keys = {}
    for key_id in sorted(index, key=lambda i: index[i]["kind"] == "collection"):
        entry = index[key_id]
        kind, parent, wrapped = (entry[k] for k in ("kind", "parent", "wrapped"))
        if wrapped is not None:
            keys[key_id] = unwrap(mk if parent == "master" else keys[parent], b64(wrapped), key_id, kind, parent)
            if kind == "profile":
                label = unwrap(vk(mk, "profile-label"), b64(entry["label_enc"]), key_id, "profile-label", parent)
                check(bool(utf8(label)))
    def collection_key(key_id):
        entry = index.get(key_id, {})
        check(entry.get("state") != "destroyed", "ERASED")
        check(entry.get("kind") == "collection", "KEY")
        return vk(keys[key_id], "collection-encryption")
    return collection_key
def utf8(raw):
    try: return raw.decode()
    except UnicodeError: raise InvalidVault("SCHEMA")
def records(stream):
    offset = 0
    while offset < len(stream):
        h = stream[offset:offset + 69]
        check(len(h) == 69, "LENGTH")
        check(h[:4] == b"FVR1", "VERSION")
        kind, context = h[4], int.from_bytes(h[53:61], "big")
        check((kind == 1 and context > 0) or (kind == 2 and context == 0))
        offset += 69
        end = offset + int.from_bytes(h[61:], "big")
        check(offset + 20 <= end <= len(stream), "LENGTH")
        frames = []
        while offset < end:
            check(end - offset >= 20, "LENGTH")
            size = int.from_bytes(stream[offset:offset + 4], "big")
            nxt = offset + 20 + size
            check(nxt <= end and size <= FRAME and (nxt == end or size == FRAME)
                  and (size > 0 or kind == 2 and not frames), "LENGTH")
            frames.append(stream[offset + 4:nxt])
            offset = nxt
        yield kind, context, h[5:21].hex(), h, frames
def plaintext(record, vault_id, key_for_id):
    kind, context, key_id, header, frames = record
    key = derive(key_for_id(key_id), "record-key", header[21:53])
    chunks = []
    for i, frame in enumerate(frames):
        index = i.to_bytes(8, "big")
        aad = header + bytes.fromhex(vault_id) + index + bytes([i == len(frames) - 1])
        chunks.append(decrypt(key, bytes(4) + index, frame, aad))
    raw = b"".join(chunks)
    if kind == 1:
        try: event = json.loads(utf8(raw), parse_constant=lambda _: check(False))
        except (ValueError, RecursionError): raise InvalidVault("SCHEMA")
        check(isinstance(event, dict) and "seq" in event)
        check(integer(event["seq"]) and event["seq"] == context, "SEQUENCE")
    return raw

def verify_segment(raw, signature, public_key, vault_id, files, previous=(0, "0" * 64, 0), key_for_id=None):
    manifest = document(raw, "foundry-segment/1", "vault_id epoch segment prev_manifest_sha256 first_event_seq "
                        "last_event_seq files key_ids closed_at writer")
    check(integer(manifest["epoch"]) and manifest["epoch"] == 1 and integer(manifest["segment"]))
    check(matches(manifest["vault_id"], "[0-9a-f]{32}") and matches(manifest["prev_manifest_sha256"], "[0-9a-f]{64}"))
    date(manifest["closed_at"])
    check(isinstance(manifest["writer"], str) and bool(manifest["writer"]))
    first, last = manifest["first_event_seq"], manifest["last_event_seq"]
    check(first is None and last is None or integer(first) and integer(last, first))
    check(len(public_key) == 32, "KEY")
    try: Ed25519PublicKey.from_public_bytes(public_key).verify(signature, raw)
    except InvalidSignature: raise InvalidVault("SIGNATURE")
    number, link, sequence = previous
    check(manifest["vault_id"] == vault_id and manifest["segment"] == number + 1 and
          manifest["prev_manifest_sha256"] == link and (first is None or first == sequence + 1), "CHAIN")
    entries = manifest["files"]
    check(isinstance(entries, list) and entries)
    names = {}
    for entry in entries:
        shape(entry, "name bytes sha256")
        name = entry["name"]
        check(matches(name, r"(events|pack)-[0-9]{4,16}\.fvr") and integer(entry["bytes"], 89)
              and matches(entry["sha256"], "[0-9a-f]{64}"))
        ordinal = int(name.split("-")[1][:-4])
        check(integer(ordinal) and name == f"{name.split('-')[0]}-{ordinal:04}.fvr")
        names[name] = ordinal
    check(list(names) == sorted(names) and len(names) == len(entries))
    check(files.keys() == names.keys(), "FILE")
    ids, decoded = set(), []
    for entry in sorted(entries, key=lambda f: names[f["name"]]):
        name = entry["name"]
        stream = files[name]
        check(len(stream) == entry["bytes"] and hashlib.sha256(stream).hexdigest() == entry["sha256"], "FILE")
        for record in records(stream):
            kind, context, key_id, _, _ = record
            check(kind == (1 if name.startswith("events-") else 2))
            ids.add(key_id)
            if kind == 1:
                sequence += 1
                check(first is not None and context == sequence, "SEQUENCE")
            if key_for_id is not None: decoded.append(plaintext(record, vault_id, key_for_id))
    check(last is None or last == sequence, "SEQUENCE")
    check(manifest["key_ids"] == sorted(ids), "KEY")
    return (number + 1, hashlib.sha256(raw).hexdigest(), sequence), decoded
