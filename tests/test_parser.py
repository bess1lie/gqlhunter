from gqlhunter.schema.parser import parse

MOCK_INTROSPECTION = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "subscriptionType": None,
    "types": [
        {
            "kind": "OBJECT",
            "name": "Query",
            "description": "Root query type",
            "fields": [
                {
                    "name": "user",
                    "description": "Get user by ID",
                    "args": [
                        {
                            "name": "id",
                            "type": {
                                "kind": "NON_NULL",
                                "name": None,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "ID",
                                    "ofType": None,
                                },
                            },
                        }
                    ],
                    "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                    "isDeprecated": False,
                    "deprecationReason": None,
                },
                {
                    "name": "users",
                    "description": "List all users",
                    "args": [],
                    "type": {
                        "kind": "LIST",
                        "name": None,
                        "ofType": {"kind": "OBJECT", "name": "User", "ofType": None},
                    },
                    "isDeprecated": False,
                    "deprecationReason": None,
                },
            ],
            "inputFields": None,
            "interfaces": [],
            "enumValues": None,
            "possibleTypes": None,
        },
        {
            "kind": "OBJECT",
            "name": "Mutation",
            "description": "Root mutation type",
            "fields": [
                {
                    "name": "deleteUser",
                    "description": "Delete a user",
                    "args": [
                        {
                            "name": "userId",
                            "type": {
                                "kind": "NON_NULL",
                                "name": None,
                                "ofType": {
                                    "kind": "SCALAR",
                                    "name": "ID",
                                    "ofType": None,
                                },
                            },
                        }
                    ],
                    "type": {"kind": "SCALAR", "name": "Boolean", "ofType": None},
                    "isDeprecated": False,
                    "deprecationReason": None,
                },
                {
                    "name": "createUser",
                    "description": "Create a new user",
                    "args": [
                        {
                            "name": "input",
                            "type": {
                                "kind": "NON_NULL",
                                "name": None,
                                "ofType": {
                                    "kind": "INPUT_OBJECT",
                                    "name": "CreateUserInput",
                                    "ofType": None,
                                },
                            },
                        }
                    ],
                    "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                    "isDeprecated": False,
                    "deprecationReason": None,
                },
            ],
            "inputFields": None,
            "interfaces": [],
            "enumValues": None,
            "possibleTypes": None,
        },
        {
            "kind": "OBJECT",
            "name": "User",
            "description": "User type",
            "fields": [
                {
                    "name": "id",
                    "description": "User ID",
                    "args": [],
                    "type": {"kind": "SCALAR", "name": "ID", "ofType": None},
                    "isDeprecated": False,
                    "deprecationReason": None,
                },
                {
                    "name": "email",
                    "description": "User email",
                    "args": [],
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                    "isDeprecated": False,
                    "deprecationReason": None,
                },
            ],
            "inputFields": None,
            "interfaces": [],
            "enumValues": None,
            "possibleTypes": None,
        },
        {
            "kind": "SCALAR",
            "name": "ID",
            "description": None,
            "fields": None,
            "inputFields": None,
            "interfaces": None,
            "enumValues": None,
            "possibleTypes": None,
        },
        {
            "kind": "SCALAR",
            "name": "String",
            "description": None,
            "fields": None,
            "inputFields": None,
            "interfaces": None,
            "enumValues": None,
            "possibleTypes": None,
        },
        {
            "kind": "SCALAR",
            "name": "Boolean",
            "description": None,
            "fields": None,
            "inputFields": None,
            "interfaces": None,
            "enumValues": None,
            "possibleTypes": None,
        },
        {
            "kind": "INPUT_OBJECT",
            "name": "CreateUserInput",
            "description": None,
            "fields": None,
            "inputFields": [
                {
                    "name": "name",
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                },
                {
                    "name": "email",
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                },
            ],
            "interfaces": None,
            "enumValues": None,
            "possibleTypes": None,
        },
    ],
}


def test_parses_queries() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    assert len(parsed.queries) == 2
    assert parsed.queries[0].name == "user"
    assert parsed.queries[1].name == "users"


def test_parses_mutations() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    assert len(parsed.mutations) == 2
    assert parsed.mutations[0].name == "deleteUser"
    assert parsed.mutations[1].name == "createUser"


def test_parses_query_args() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    user_op = parsed.queries[0]
    assert len(user_op.args) == 1
    assert user_op.args[0].name == "id"
    assert user_op.args[0].type.kind == "NON_NULL"


def test_parses_return_types() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    assert parsed.queries[0].return_type is not None
    assert parsed.queries[0].return_type.name == "User"


def test_skips_introspection_types() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    for t in parsed.types:
        assert not t.name.startswith("__")


def test_query_type_name() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    assert parsed.query_type == "Query"


def test_mutation_type_name() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    assert parsed.mutation_type == "Mutation"


def test_subscription_none() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    assert parsed.subscription_type is None


def test_non_object_types_included() -> None:
    parsed = parse(MOCK_INTROSPECTION)
    names = {t.name for t in parsed.types}
    assert "ID" in names
    assert "String" in names
    assert "Boolean" in names
    assert "CreateUserInput" in names
