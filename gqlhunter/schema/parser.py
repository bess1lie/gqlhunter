from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ArgType:
    kind: str
    name: str | None
    of_type: str | None = None

    @classmethod
    def from_ref(cls, ref: dict[str, Any]) -> ArgType:
        return cls(
            kind=ref.get("kind", ""),
            name=ref.get("name"),
            of_type=_unwind_of_type(ref),
        )


@dataclass
class FieldArg:
    name: str
    type: ArgType


@dataclass
class Field:
    name: str
    description: str | None
    args: list[FieldArg] = field(default_factory=list)
    return_type: ArgType | None = None
    is_deprecated: bool = False
    deprecation_reason: str | None = None


@dataclass
class SchemaType:
    kind: str
    name: str
    description: str | None
    fields: list[Field]


@dataclass
class ParsedSchema:
    query_type: str | None
    mutation_type: str | None
    subscription_type: str | None
    types: list[SchemaType]
    queries: list[Field]
    mutations: list[Field]
    subscriptions: list[Field]


def parse(data: dict[str, Any]) -> ParsedSchema:
    query_type_name = (data.get("queryType") or {}).get("name") or "Query"
    mutation_type_name = (data.get("mutationType") or {}).get("name")
    subscription_type_name = (data.get("subscriptionType") or {}).get("name")

    raw_types = data.get("types", [])

    queries: list[Field] = []
    mutations: list[Field] = []
    subscriptions: list[Field] = []
    types: list[SchemaType] = []

    for raw in raw_types:
        kind = raw.get("kind", "")
        name = raw.get("name", "")

        if name.startswith("__"):
            continue

        fields: list[Field] = []
        for f in raw.get("fields") or []:
            field = Field(
                name=f["name"],
                description=f.get("description"),
                args=[FieldArg(name=a["name"], type=ArgType.from_ref(a.get("type", {}))) for a in f.get("args") or []],
                return_type=ArgType.from_ref(f.get("type", {})),
                is_deprecated=f.get("isDeprecated", False),
                deprecation_reason=f.get("deprecationReason"),
            )
            fields.append(field)

        st = SchemaType(kind=kind, name=name, description=raw.get("description"), fields=fields)
        types.append(st)

        if name == query_type_name:
            queries = fields
        elif mutation_type_name and name == mutation_type_name:
            mutations = fields
        elif subscription_type_name and name == subscription_type_name:
            subscriptions = fields

    return ParsedSchema(
        query_type=query_type_name,
        mutation_type=mutation_type_name,
        subscription_type=subscription_type_name,
        types=types,
        queries=queries,
        mutations=mutations,
        subscriptions=subscriptions,
    )


def _unwind_of_type(ref: dict[str, Any]) -> str | None:
    parts: list[str] = []
    current = ref
    while current:
        kind = current.get("kind", "")
        name = current.get("name")
        if kind == "NON_NULL":
            parts.append("!")
        elif kind == "LIST":
            parts.append("[]")
        elif name:
            return "".join(parts) + name
        current = current.get("ofType")
    return None
