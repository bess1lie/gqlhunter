import json

from gqlhunter.cli import diff_operations


def _op(
    type_: str = "query",
    name: str = "users",
    args: list[dict] | None = None,
    return_type: str = "String",
) -> dict:
    return {
        "type": type_,
        "name": name,
        "args_json": json.dumps(args) if args else None,
        "return_type": return_type,
    }


class TestAdded:
    def test_added_single(self) -> None:
        old = [_op(name="users")]
        new = [_op(name="users"), _op(name="posts")]
        result = diff_operations(old, new)
        assert len(result) == 1
        assert result[0]["change"] == "added"
        assert result[0]["name"] == "posts"

    def test_added_multiple(self) -> None:
        old = [_op(name="users")]
        new = [_op(name="users"), _op(name="posts"), _op(type_="mutation", name="createUser")]
        result = diff_operations(old, new)
        assert len(result) == 2
        assert all(c["change"] == "added" for c in result)


class TestRemoved:
    def test_removed_single(self) -> None:
        old = [_op(name="users"), _op(name="posts")]
        new = [_op(name="users")]
        result = diff_operations(old, new)
        assert len(result) == 1
        assert result[0]["change"] == "removed"
        assert result[0]["name"] == "posts"

    def test_removed_multiple(self) -> None:
        old = [_op(name="users"), _op(name="posts")]
        new: list[dict] = []
        result = diff_operations(old, new)
        assert len(result) == 2
        assert all(c["change"] == "removed" for c in result)


class TestModified:
    def test_args_changed(self) -> None:
        old = [_op(type_="mutation", name="updateUser", args=[{"name": "id", "type": "ID"}])]
        new = [_op(
            type_="mutation", name="updateUser",
            args=[{"name": "id", "type": "ID"}, {"name": "role", "type": "String"}],
        )]
        result = diff_operations(old, new)
        assert len(result) == 1
        assert result[0]["change"] == "modified"
        assert "args changed" in result[0]["detail"]

    def test_return_type_changed(self) -> None:
        old = [_op(name="users", return_type="String")]
        new = [_op(name="users", return_type="[User]")]
        result = diff_operations(old, new)
        assert len(result) == 1
        assert result[0]["change"] == "modified"
        assert "return:" in result[0]["detail"]

    def test_args_and_return_changed(self) -> None:
        old = [_op(name="users", args=[{"name": "limit", "type": "Int"}], return_type="String")]
        new = [_op(
            name="users",
            args=[{"name": "limit", "type": "Int"}, {"name": "offset", "type": "Int"}],
            return_type="[User]",
        )]
        result = diff_operations(old, new)
        assert len(result) == 1
        assert "args changed" in result[0]["detail"]
        assert "return:" in result[0]["detail"]


class TestFalsePositiveGuard:
    def test_no_false_modified_on_json_key_order(self) -> None:
        """Different key order in JSON string should NOT trigger MODIFIED."""
        old = [_op(type_="mutation", name="updateUser", args=[{"type": "ID", "name": "id"}])]
        new = [_op(type_="mutation", name="updateUser", args=[{"name": "id", "type": "ID"}])]
        result = diff_operations(old, new)
        assert len(result) == 0

class TestNoChanges:
    def test_identical_ops(self) -> None:
        old = [_op(name="users"), _op(type_="mutation", name="createUser")]
        new = [_op(name="users"), _op(type_="mutation", name="createUser")]
        result = diff_operations(old, new)
        assert len(result) == 0

    def test_both_empty(self) -> None:
        assert diff_operations([], []) == []


class TestSortOrder:
    def test_added_first_then_modified_then_removed(self) -> None:
        old = [
            _op(name="removed_op"),
            _op(type_="mutation", name="modified_op", args=[{"name": "id", "type": "ID"}]),
        ]
        new = [
            _op(name="added_op"),
            _op(
                type_="mutation", name="modified_op",
                args=[{"name": "id", "type": "ID"}, {"name": "x", "type": "String"}],
            ),
        ]
        result = diff_operations(old, new)
        assert len(result) == 3
        assert result[0]["change"] == "added"
        assert result[1]["change"] == "modified"
        assert result[2]["change"] == "removed"
