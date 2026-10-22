"""Process hardening before any secret enters memory (design §5.1 step 2).

``recorder run``, ``recorder init`` and ``recorder rekey`` call it first: no core dumps (the
limit is inherited by their age children), and on Linux the process is marked non-dumpable.
"""

import ctypes
import resource
import sys
from typing import Final

from airtimesat_platform.recorder.errors import RecorderError

PR_SET_DUMPABLE: Final = 4


def harden_process() -> None:
    """No core dumps; on Linux, mark the process non-dumpable (design §5.1 step 2).

    Non-dumpable also stops other processes of the same user from reading its memory. Where
    the OS has no such call, it is skipped.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise RecorderError("HARDENING_FAILED")
