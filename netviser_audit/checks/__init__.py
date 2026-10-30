"""Check registry. Add new checks to ``ALL_CHECKS``; order defines report order."""
from typing import Iterable, List

from .base import Check
from .cve_2026_98432 import Cve202698432Check
from .kernel import KernelCheck
from .mptcp import MptcpCheck
from .patch import PatchCheck
from .tcp_migration import TcpMigrationCheck

ALL_CHECKS = (KernelCheck(), PatchCheck(), TcpMigrationCheck(), MptcpCheck(),
              Cve202698432Check())
CHECKS_BY_ID = {c.id: c for c in ALL_CHECKS}


def select_checks(ids: Iterable[str]) -> List[Check]:
    """Return the requested checks plus their dependencies, in registry order."""
    wanted = set()
    pending = list(ids)
    while pending:
        check_id = pending.pop()
        if check_id not in CHECKS_BY_ID:
            raise KeyError(check_id)
        if check_id not in wanted:
            wanted.add(check_id)
            pending.extend(CHECKS_BY_ID[check_id].requires)
    return [c for c in ALL_CHECKS if c.id in wanted]
