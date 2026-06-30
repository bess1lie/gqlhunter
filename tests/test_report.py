from gqlhunter.report.render import render_html


class TestHtmlXssGuard:
    def test_script_in_operation_name_is_escaped(self) -> None:
        html = render_html(
            target="https://evil.example.com/graphql",
            scan_run_id=1,
            date="2026-01-01",
            endpoints=[{"url": "https://evil.example.com/graphql", "status": "enabled"}],
            schema={
                "query_type": "Query",
                "mutation_type": "Mutation",
                "subscription_type": None,
                "total_types": 2,
                "queries": [
                    {"name": "<script>alert(1)</script>", "return_type": "String", "args": []},
                ],
                "mutations": [],
            },
            findings=[],
        )
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "<script>alert(1)</script>" not in html

    def test_script_in_description_is_escaped(self) -> None:
        html = render_html(
            target="https://evil.example.com/graphql",
            scan_run_id=1,
            date="2026-01-01",
            endpoints=[
                {"url": "https://evil.example.com/graphql", "status": 'enabled"><script>alert(1)</script>'},
            ],
            schema={
                "query_type": "Query",
                "mutation_type": None,
                "subscription_type": None,
                "total_types": 0,
                "queries": [],
                "mutations": [],
            },
            findings=[],
        )
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "<script>alert(1)</script>" not in html

    def test_normal_html_structure_preserved(self) -> None:
        html = render_html(
            target="https://example.com/graphql",
            scan_run_id=42,
            date="2026-06-30",
            endpoints=[{"url": "https://example.com/graphql", "status": "enabled"}],
            schema={
                "query_type": "Query",
                "mutation_type": "Mutation",
                "subscription_type": None,
                "total_types": 5,
                "queries": [
                    {"name": "users", "return_type": "[User]", "args": ["id: ID"]},
                ],
                "mutations": [
                    {"name": "createUser", "return_type": "User", "args": ["name: String"]},
                ],
            },
            findings=[
                {"severity": "high", "category": "admin_mutation", "detail": "Potential admin mutation"},
            ],
        )
        assert "<!DOCTYPE html>" in html
        assert "42" in html
        assert "users" in html
        assert "createUser" in html
        assert "high" in html
        assert "Potential admin mutation" in html
