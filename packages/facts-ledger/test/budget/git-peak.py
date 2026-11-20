#!/usr/bin/env python3
# Budget check (Step Zero 10.4), Linux only: run the real git with the same arguments and
# append its peak resident set size (KiB, from wait4) to FACTS_BUDGET_GIT_LOG.
import os
import sys

REAL_GIT = os.environ["FACTS_BUDGET_REAL_GIT"]
LOG = os.environ["FACTS_BUDGET_GIT_LOG"]

pid = os.fork()
if pid == 0:
    os.execv(REAL_GIT, [REAL_GIT] + sys.argv[1:])
_, status, usage = os.wait4(pid, 0)
with open(LOG, "a", encoding="ascii") as f:
    f.write(f"{usage.ru_maxrss}\n")
code = os.waitstatus_to_exitcode(status)
sys.exit(code if code >= 0 else 128 - code)
