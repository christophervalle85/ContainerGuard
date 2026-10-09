from importlib import import_module

import pytest
from pydantic import ValidationError

RULES = dict(
    max_critical=0, max_high=5, require_sbom=True, unknown_severity_action="fail"
)


def schemas():
    return import_module("app.policies.schemas")


@pytest.mark.parametrize("field", list(RULES))
def test_every_rule_is_required(field):
    data = RULES.copy()
    del data[field]
    with pytest.raises(ValidationError):
        schemas().PolicyRules(**data)


@pytest.mark.parametrize("field", ["max_critical", "max_high"])
@pytest.mark.parametrize("value", [True, False, "5", 1.5, 5.0, -1, 2147483648, None])
def test_threshold_rejects_coercion_and_out_of_range_values(field, value):
    data = RULES | {field: value}
    with pytest.raises(ValidationError):
        schemas().PolicyRules(**data)


@pytest.mark.parametrize("value", [0, 2147483647])
def test_threshold_accepts_inclusive_integer_bounds(value):
    rules = schemas().PolicyRules(
        **(RULES | {"max_critical": value, "max_high": value})
    )
    assert rules.max_critical == value and rules.max_high == value


@pytest.mark.parametrize("value", [0, 1, "true", "false", None])
def test_sbom_requirement_is_strict_boolean(value):
    with pytest.raises(ValidationError):
        schemas().PolicyRules(**(RULES | {"require_sbom": value}))


@pytest.mark.parametrize("value", ["FAIL", "allow", " ignore ", None, True])
def test_unknown_severity_action_is_explicit(value):
    with pytest.raises(ValidationError):
        schemas().PolicyRules(**(RULES | {"unknown_severity_action": value}))


@pytest.mark.parametrize("value", ["fail", "ignore"])
def test_supported_unknown_actions(value):
    assert (
        schemas()
        .PolicyRules(**(RULES | {"unknown_severity_action": value}))
        .unknown_severity_action
        == value
    )


@pytest.mark.parametrize("value", [True, False])
def test_supported_sbom_boolean(value):
    assert (
        schemas().PolicyRules(**(RULES | {"require_sbom": value})).require_sbom is value
    )


@pytest.mark.parametrize(
    "model, data",
    [
        ("PolicyRules", RULES),
        ("PolicyCreate", {"name": "release", "rules": RULES}),
        ("PolicyVersionCreate", {"rules": RULES}),
    ],
)
def test_unexpected_fields_never_disappear(model, data):
    with pytest.raises(ValidationError):
        getattr(schemas(), model)(**(data | {"typo": 5}))


@pytest.mark.parametrize("name", ["", "  ", "x" * 101, None, 123])
def test_policy_name_rejects_empty_long_or_nontext_values(name):
    with pytest.raises(ValidationError):
        schemas().PolicyCreate(name=name, rules=RULES)


@pytest.mark.parametrize("name", ["x", "x" * 100])
def test_policy_names_are_trimmed_with_valid_boundary_lengths(name):
    assert schemas().PolicyCreate(name="  " + name + "  ", rules=RULES).name == name
