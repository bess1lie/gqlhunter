from __future__ import annotations

from dataclasses import dataclass

from gqlhunter.schema.parser import Field

CRITICAL_PREFIXES = ["delete", "remove", "destroy", "drop", "truncate", "purge"]
HIGH_PREFIXES = ["admin", "setrole", "resetpassword", "resetpwd", "disable", "enable"]
MEDIUM_PREFIXES = [
    "update", "create", "add", "edit", "modify", "insert", "upsert",
    "set", "change", "register", "upload",
]
INFO_PREFIXES = ["get", "list", "search", "find", "query", "lookup"]

IDOR_ARG_NAMES = {
    "id", "userid", "user_id", "accountid", "account_id",
    "documentid", "document_id", "customerid", "customer_id",
    "profileid", "profile_id", "email", "useremail", "user_email",
    "uid", "guid", "uuid",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class RiskFinding:
    operation_type: str
    operation_name: str
    severity: str
    category: str
    detail: str | None = None
    operation_id: int | None = None


def classify_field(field: Field) -> str:
    name_lower = field.name.lower()
    for severity, prefixes in [
        ("critical", CRITICAL_PREFIXES),
        ("high", HIGH_PREFIXES),
        ("medium", MEDIUM_PREFIXES),
        ("info", INFO_PREFIXES),
    ]:
        for prefix in prefixes:
            if name_lower.startswith(prefix):
                return severity
    return "info"


def detect_idor_args(field: Field) -> list[str]:
    return [a.name for a in field.args if a.name.lower() in IDOR_ARG_NAMES]


def analyze_operations(
    queries: list[Field],
    mutations: list[Field],
    subscriptions: list[Field] | None = None,
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []

    for f in queries:
        severity = classify_field(f)
        if severity == "info":
            continue

        idor_args = detect_idor_args(f)
        detail_parts: list[str] = []
        if idor_args:
            detail_parts.append(f"IDOR candidate args: {', '.join(idor_args)}")

        findings.append(
            RiskFinding(
                operation_type="query",
                operation_name=f.name,
                severity=severity,
                category="field_name_heuristic",
                detail="; ".join(detail_parts) if detail_parts else None,
            )
        )

    for f in mutations:
        severity = classify_field(f)
        detail_parts = []
        idor_args = detect_idor_args(f)
        if idor_args:
            detail_parts.append(f"IDOR candidate args: {', '.join(idor_args)}")

        findings.append(
            RiskFinding(
                operation_type="mutation",
                operation_name=f.name,
                severity=severity,
                category="field_name_heuristic",
                detail="; ".join(detail_parts) if detail_parts else None,
            )
        )

    if subscriptions:
        for f in subscriptions:
            severity = classify_field(f)
            if severity == "info":
                continue
            idor_args = detect_idor_args(f)
            detail_parts = []
            if idor_args:
                detail_parts.append(f"IDOR candidate args: {', '.join(idor_args)}")
            findings.append(
                RiskFinding(
                    operation_type="subscription",
                    operation_name=f.name,
                    severity=severity,
                    category="field_name_heuristic",
                    detail="; ".join(detail_parts) if detail_parts else None,
                )
            )

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 99))
    return findings
