"""Synthetic SQLite-locked writer and independent JSONL reader for Z-2."""

import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path


def read(path, recover_tail=False):
    if not path.exists():
        return []
    blocks = []
    for line in path.read_bytes().splitlines(keepends=True):
        if len(line) + (not line.endswith(b"\n")) > 65536:
            continue
        if not line.endswith(b"\n") and not recover_tail:
            continue
        try:
            blocks.append(json.loads(line))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    return blocks


def write(path, count):
    ids = []
    with closing(sqlite3.connect(str(path) + ".lock.sqlite", timeout=5)) as lock:
        for index in range(count):
            lock.execute("BEGIN IMMEDIATE")
            with path.open("a+b", buffering=0) as log:
                end = log.seek(0, os.SEEK_END)
                if end:
                    log.seek(-1, os.SEEK_END)
                separator = b"\n" if end and log.read(1) != b"\n" else b""
                blocks = read(path, recover_tail=bool(separator))
                parent = next((b["id"] for b in reversed(blocks) if b["project"] == "fixture"), None)
                block = {
                    "id": f"f{index:011x}", "ts": "2026-01-01T00:00:00+00:00",
                    "agent": "python-fixture", "project": "fixture", "parent": parent,
                    "intent": "synthetic append", "reasoning": "verify lock", "status": "done",
                }
                line = separator + json.dumps(block).encode("utf-8") + b"\n"
                if log.write(line) != len(line):
                    raise OSError("short append")
                os.fsync(log.fileno())
            lock.commit()
            ids.append(block["id"])
    return ids


if __name__ == "__main__":
    path = Path(sys.argv[2])
    if sys.argv[1] == "write":
        print(json.dumps(write(path, int(sys.argv[3]))))
    else:
        print(json.dumps(read(path)))
