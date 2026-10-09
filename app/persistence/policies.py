"""Create policies and allocate immutable versions under a parent row lock."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.persistence.models import Policy, PolicyVersion
from app.policies.schemas import (
    PolicyCreate,
    PolicyPage,
    PolicyRecord,
    PolicyRules,
    PolicyVersionPage,
    PolicyVersionRecord,
)


class PolicyNotFound(LookupError):
    pass


class PolicyNameConflict(RuntimeError):
    pass


def _version_record(row: PolicyVersion) -> PolicyVersionRecord:
    return PolicyVersionRecord(
        policy_id=row.policy_id,
        policy_version_id=row.id,
        version_number=row.version_number,
        created_at=row.created_at,
        rules=PolicyRules(
            max_critical=row.max_critical,
            max_high=row.max_high,
            require_sbom=row.require_sbom,
            unknown_severity_action=row.unknown_severity_action,
        ),
    )


def _add_version(
    session: Session, policy_id: UUID, number: int, rules: PolicyRules
) -> PolicyVersionRecord:
    row = PolicyVersion(
        policy_id=policy_id, version_number=number, **rules.model_dump()
    )
    session.add(row)
    session.flush()
    return _version_record(row)


def create_policy(
    session: Session, name: str, rules: PolicyRules
) -> PolicyVersionRecord:
    validated = PolicyCreate(name=name, rules=rules)
    try:
        with session.begin():
            row = Policy(name=validated.name)
            session.add(row)
            session.flush()
            result = _add_version(session, row.id, 1, validated.rules)
    except IntegrityError as error:
        if (
            getattr(getattr(error.orig, "diag", None), "constraint_name", None)
            == "uq_policies_name"
        ):
            raise PolicyNameConflict from None
        raise
    return result


def create_policy_version(
    session: Session, policy_id: UUID, rules: PolicyRules
) -> PolicyVersionRecord:
    with session.begin():
        parent = session.scalar(
            select(Policy).where(Policy.id == policy_id).with_for_update()
        )
        if parent is None:
            raise PolicyNotFound
        last = session.scalar(
            select(func.max(PolicyVersion.version_number)).where(
                PolicyVersion.policy_id == policy_id
            )
        )
        return _add_version(session, policy_id, (last or 0) + 1, rules)


def list_policies(session: Session, *, limit: int, offset: int) -> PolicyPage:
    total = session.scalar(select(func.count()).select_from(Policy))
    rows = session.scalars(
        select(Policy)
        .order_by(Policy.created_at.desc(), Policy.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return PolicyPage(
        items=[
            PolicyRecord(policy_id=row.id, name=row.name, created_at=row.created_at)
            for row in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


def list_policy_versions(
    session: Session, policy_id: UUID, *, limit: int, offset: int
) -> PolicyVersionPage:
    if session.get(Policy, policy_id) is None:
        raise PolicyNotFound
    query = select(PolicyVersion).where(PolicyVersion.policy_id == policy_id)
    total = session.scalar(
        select(func.count())
        .select_from(PolicyVersion)
        .where(PolicyVersion.policy_id == policy_id)
    )
    rows = session.scalars(
        query.order_by(PolicyVersion.version_number.desc()).limit(limit).offset(offset)
    )
    return PolicyVersionPage(
        items=[_version_record(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
