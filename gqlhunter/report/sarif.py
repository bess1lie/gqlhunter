from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def generate_sarif(
    endpoint: str,
    scan_run_id: int,
    operations: list[dict[str, Any]],
    risk_findings: list[dict[str, Any]],
    output: Path,
) -> Path:
    """Generate a SARIF 2.1.0 report file."""

    results: list[dict] = []

    for rf in risk_findings:
        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        results.append({
            "ruleId": f"{rf['operation_type']}/{rf['operation_name']}",
            "level": level_map.get(rf["severity"], "note"),
            "message": {
                "text": f"{rf['operation_type']}.{rf['operation_name']}: {rf['category']}"
                + (f" \u2014 {rf['detail']}" if rf.get("detail") else "")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": endpoint
                    }
                }
            }],
            "properties": {
                "severity": rf["severity"],
                "category": rf["category"],
                "operation_type": rf["operation_type"],
                "operation_name": rf["operation_name"],
            },
        })

    # For operations without risk findings, add info-level entries
    op_names = {(rf["operation_type"], rf["operation_name"]) for rf in risk_findings}
    for op in operations:
        if (op["type"], op["name"]) not in op_names:
            results.append({
                "ruleId": f"{op['type']}/{op['name']}",
                "level": "note",
                "message": {
                    "text": f"{op['type']}.{op['name']}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": endpoint
                        }
                    }
                }],
                "properties": {
                    "operation_type": op["type"],
                    "operation_name": op["name"],
                },
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "gqlhunter",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/bess1lie/gqlhunter",
                    "rules": [
                        {
                            "id": r["ruleId"],
                            "name": r["ruleId"],
                            "shortDescription": {"text": r["message"]["text"]},
                            "properties": r["properties"],
                        }
                        for r in results
                    ],
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTime": datetime.now(UTC).isoformat(),
            }],
        }],
    }

    output.write_text(json.dumps(sarif, indent=2))
    return output
