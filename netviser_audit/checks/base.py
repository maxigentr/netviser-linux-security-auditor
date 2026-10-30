"""Types shared by all checks."""
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

OK = "OK"
INFO = "INFO"
REVIEW = "REVIEW"
UNKNOWN = "UNKNOWN"

Facts = Dict[str, str]


@dataclass
class Finding:
    key: str      # stable identifier, e.g. "mptcp.usage"
    status: str   # OK / INFO / REVIEW / UNKNOWN
    verdict: str  # machine-readable code, e.g. "IN_USE"
    title: str
    detail: str = ""

    def to_dict(self):
        return asdict(self)


class Check:
    """A check contributes a POSIX sh collector snippet and evaluates the facts it produced.

    Collectors run on the target and must be strictly read-only. They emit facts
    with ``nv_kv <key> <value>`` (see ``system.PRELUDE``). Evaluation runs on the
    controller and must treat every fact as untrusted text.
    """

    id = ""
    title = ""
    requires: Tuple[str, ...] = ()      # check ids whose facts this check reads
    collector = ""
    report_facts: Tuple[str, ...] = ()  # facts exported as CSV columns
    finding_keys: Tuple[str, ...] = ()  # findings exported as CSV columns

    def evaluate(self, facts: Facts) -> List[Finding]:
        raise NotImplementedError


def to_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def split_list(value: Optional[str]) -> List[str]:
    return [x for x in (value or "").split(",") if x]
