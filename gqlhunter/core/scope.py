from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


@dataclass
class Scope:
    allowlist: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    template_dir: str | None = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> Scope:
        path = Path(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        if not data:
            return cls()
        return cls(
            allowlist=data.get("allowlist", []),
            targets=data.get("targets", []),
            template_dir=data.get("template_dir") or (data.get("notify") or {}).get("template_dir"),
        )

    def is_in_scope(self, url: str) -> bool:
        host = urlparse(url).hostname
        if not host:
            return False
        return self.can_scan(host)

    def can_scan(self, host: str) -> bool:
        if not self.targets and not self.allowlist:
            return False

        deny_patterns = [p.lstrip("!") for p in self.targets if self._is_deny_pattern(p)]
        allow_patterns = [p for p in self.targets if not self._is_deny_pattern(p)]

        for pattern in deny_patterns:
            if fnmatch.fnmatch(host, pattern):
                return False

        if allow_patterns:
            in_allow = any(fnmatch.fnmatch(host, p) for p in allow_patterns)
            if not in_allow:
                return False
            return True

        if self.allowlist:
            return any(fnmatch.fnmatch(host, p) for p in self.allowlist)

        return False

    @staticmethod
    def _is_deny_pattern(pattern: str) -> bool:
        return pattern.startswith("!")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowlist": self.allowlist,
            "targets": self.targets,
        }
