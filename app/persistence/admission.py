"""Serialize real-scan admissions against the durable active-scan count."""

import os
import re

from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.persistence.models import Scan


class ScanCapacityExceeded(RuntimeError):
    pass


class ScanAdmissionUnavailable(RuntimeError):
    pass


def get_max_active_scans() -> int:
    raw = os.environ.get("MAX_ACTIVE_SCANS", "20")
    if re.fullmatch(r"[0-9]+", raw) is None or not 1 <= int(raw) <= 1000:
        raise ValueError("MAX_ACTIVE_SCANS must be an integer from 1 to 1000")
    return int(raw)


def reserve_scan_capacity(session: Session, *, limit: int) -> None:
    """Call within the same transaction that inserts the new active scan."""
    if not session.in_transaction() or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Admission requires a transaction and valid capacity")
    if session.connection().get_isolation_level() != "READ COMMITTED":
        raise ScanAdmissionUnavailable("Scan admission temporarily unavailable")
    try:
        session.execute(text("SET LOCAL lock_timeout = '2s'"))
        session.execute(text("SELECT pg_advisory_xact_lock(1128746545)"))
    except DBAPIError as error:
        if getattr(error.orig, "sqlstate", None) == "55P03":
            raise ScanAdmissionUnavailable(
                "Scan admission temporarily unavailable"
            ) from None
        raise
    count = session.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.scanner_name == "trivy", Scan.status.in_(("queued", "running")))
    )
    if count >= limit:
        raise ScanCapacityExceeded("Scan queue is full. Try again shortly.")
