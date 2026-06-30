from pathlib import Path

from gqlhunter.core.scope import Scope


def test_empty_scope_denies_all() -> None:
    s = Scope()
    assert s.can_scan("example.com") is False
    assert s.is_in_scope("https://example.com") is False


def test_allowlist_only() -> None:
    s = Scope(allowlist=["*.example.com"])
    assert s.can_scan("sub.example.com") is True
    assert s.can_scan("evil.com") is False


def test_target_match() -> None:
    s = Scope(targets=["api.example.com"])
    assert s.can_scan("api.example.com") is True
    assert s.can_scan("other.com") is False


def test_deny_override() -> None:
    s = Scope(targets=["*.example.com", "!admin.example.com"])
    assert s.can_scan("api.example.com") is True
    assert s.can_scan("admin.example.com") is False


def test_wildcard_target() -> None:
    s = Scope(targets=["*.example.com"])
    assert s.can_scan("anything.example.com") is True
    assert s.can_scan("example.com") is False


def test_deny_only() -> None:
    s = Scope(targets=["!evil.com"])
    assert s.can_scan("good.com") is False
    assert s.can_scan("evil.com") is False


def test_deny_with_allowlist() -> None:
    s = Scope(allowlist=["*.example.com"], targets=["!internal.example.com"])
    assert s.can_scan("api.example.com") is True
    assert s.can_scan("internal.example.com") is False


def test_is_in_scope() -> None:
    s = Scope(targets=["*.example.com"])
    assert s.is_in_scope("https://api.example.com/graphql") is True
    assert s.is_in_scope("https://evil.com/graphql") is False


def test_from_yaml(tmp_path: Path) -> None:
    yml = tmp_path / "scope.yaml"
    yml.write_text("targets:\n  - '*.example.com'\nallowlist:\n  - '*.example.com'\n")
    s = Scope.from_yaml(str(yml))
    assert "*.example.com" in s.targets
    assert "*.example.com" in s.allowlist
