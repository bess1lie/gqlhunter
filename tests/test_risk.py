from gqlhunter.analyzer.risk import analyze_operations, classify_field, detect_idor_args
from gqlhunter.schema.parser import ArgType, Field, FieldArg


def _field(name: str, args: list | None = None) -> Field:
    return Field(
        name=name,
        description=None,
        args=args or [],
        return_type=ArgType(kind="SCALAR", name="String"),
    )


def _arg(name: str) -> FieldArg:
    return FieldArg(name=name, type=ArgType(kind="SCALAR", name="String"))


# ── classify_field ──


def test_delete_is_critical() -> None:
    assert classify_field(_field("deleteUser")) == "critical"


def test_remove_is_critical() -> None:
    assert classify_field(_field("removeAccount")) == "critical"


def test_admin_is_high() -> None:
    assert classify_field(_field("adminPanel")) == "high"


def test_set_role_is_high() -> None:
    assert classify_field(_field("setRole")) == "high"


def test_reset_password_is_high() -> None:
    assert classify_field(_field("resetPassword")) == "high"


def test_update_is_medium() -> None:
    assert classify_field(_field("updateProfile")) == "medium"


def test_create_is_medium() -> None:
    assert classify_field(_field("createUser")) == "medium"


def test_get_is_info() -> None:
    assert classify_field(_field("getUser")) == "info"


def test_list_is_info() -> None:
    assert classify_field(_field("listUsers")) == "info"


def test_unknown_prefix_is_info() -> None:
    assert classify_field(_field("ping")) == "info"
    assert classify_field(_field("echo")) == "info"


# ── detect_idor_args ──


def test_idor_detects_id() -> None:
    f = _field("getUser", [_arg("id")])
    assert detect_idor_args(f) == ["id"]


def test_idor_detects_user_id() -> None:
    f = _field("getUser", [_arg("userId")])
    assert detect_idor_args(f) == ["userId"]


def test_idor_detects_email() -> None:
    f = _field("getUser", [_arg("email")])
    assert detect_idor_args(f) == ["email"]


def test_idor_ignores_non_idor_args() -> None:
    f = _field("searchUsers", [_arg("query"), _arg("limit")])
    assert detect_idor_args(f) == []


def test_idor_multiple() -> None:
    f = _field("updateUser", [_arg("userId"), _arg("name"), _arg("email")])
    assert "userId" in detect_idor_args(f)
    assert "email" in detect_idor_args(f)
    assert "name" not in detect_idor_args(f)


# ── analyze_operations ──


def test_analyze_skips_info_queries() -> None:
    findings = analyze_operations(
        queries=[_field("getUser")],
        mutations=[],
    )
    assert len(findings) == 0


def test_analyze_marks_mutations() -> None:
    findings = analyze_operations(
        queries=[],
        mutations=[_field("deleteUser")],
    )
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].operation_name == "deleteUser"


def test_analyze_sorts_by_severity() -> None:
    findings = analyze_operations(
        queries=[_field("listUsers")],
        mutations=[_field("deleteUser"), _field("updateProfile")],
    )
    severities = [f.severity for f in findings]
    assert severities == ["critical", "medium"]


def test_analyze_adds_idor_detail() -> None:
    findings = analyze_operations(
        queries=[_field("getUser", [_arg("userId")])],
        mutations=[],
    )
    assert len(findings) == 0  # get* is info, skipped


def test_analyze_mutation_with_idor_detail() -> None:
    findings = analyze_operations(
        queries=[],
        mutations=[_field("deleteUser", [_arg("userId")])],
    )
    assert len(findings) == 1
    assert "IDOR candidate" in (findings[0].detail or "")


def test_analyze_category() -> None:
    findings = analyze_operations(
        queries=[],
        mutations=[_field("deleteUser")],
    )
    assert findings[0].category == "field_name_heuristic"
