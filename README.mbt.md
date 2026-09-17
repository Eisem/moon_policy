# MoonPolicy

MoonPolicy is a lightweight, explainable authorization policy engine for
MoonBit. It evaluates role grants and explicit rules with deny-by-default,
explicit-deny-wins semantics.

```mbt check
///|
test {
  let policy = @moon_policy.Policy(
    role_permissions={ "editor": ["document:read"] },
    bindings=[RoleBinding(subject="alice", role="editor")],
  )
  let decision = policy.authorize(
    Request(subject="alice", action="document:read", resource="document:42"),
  )
  assert_true(decision.allowed)
}
```

## Native CLI

```sh
moon run --target native cmd/main -- demo
moon run --target native cmd/main -- check '{"rules":[]}'
moon run --target native cmd/main -- eval '{"rules":[]}' '{"subject":"alice","action":"read","resource":"doc:1"}'
```

The CLI exits with 0 for a valid policy or allowed decision, 1 for a denied
decision, and 2 for an invalid command, policy, or request. JSON is passed as
command-line text. The `examples/` directory also contains policy and request
fixtures for integration tests and future file-input support.

For exit-code-sensitive automation, run the built native executable directly.
The installed June 2026 `moon run` wrapper returns 0 even when this CLI exits 1.

## Scope

The current version provides RBAC with role inheritance, attribute conditions,
explicit allow/deny rules, JSON policy/request parsing, and a native CLI.

Roles can inherit permissions transitively. For example, define
`"role_parents": { "admin": ["editor"] }` alongside `roles` in JSON, or pass
`role_parents={ "admin": ["editor"] }` to `Policy`. Every referenced role must
be declared in `roles`; cycles are rejected during validation. Inherited grants
appear in the decision trace under the role that owns the permission.

Rules can use `Glob("...")` where `*` matches any sequence and `?` matches
one Unicode character. This is useful for HTTP-like resources and namespaced
actions such as `project:read:*`.
In JSON, write `{ "glob": "project:read:*" }` in a rule's `action` or
`resource` field; plain JSON strings always mean exact matching.

Rules may also require scalar attributes under `subject.<key>`,
`resource.<key>`, or `context.<key>`. Missing attributes never satisfy an
`Equals` or `Exists` condition, so evaluation remains fail-closed.
Negating a missing attribute remains unknown rather than becoming true.
An unknown condition never grants access; on a matching deny rule it denies
conservatively.

The JSON format expresses conditions as `exists`, `equals`, `same`, `one_of`,
`compare`, `all`, `any`, and `not` objects. A resource-owner rule can use
`{ "same": { "left": "subject.id", "right": "resource.owner_id" } }`.
Both values must exist and have the same scalar type. Integer thresholds use
`{ "compare": { "path": "context.risk", "op": "lte", "value": 20 } }`;
`op` may be `lt`, `lte`, `gt`, or `gte`. Missing or non-integer attributes are
unknown and never satisfy an allow condition, even under `not`. Attribute
values can be strings, booleans, or integers.

For an allowlist of regions or teams, use
`{ "one_of": { "path": "context.region", "values": ["eu", "apac"] } }`.
The list must be nonempty and all entries must have the same scalar type.
Call `policy.validate()` for structured configuration diagnostics. JSON loading
rejects invalid policy configuration before returning a policy.

`request_from_json` decodes an authorization request, and `decision.to_json()`
returns `allowed`, `reason`, and the ordered `trace` of matching grants/rules.

## JSON policies

`policy_from_json` loads a constrained JSON format. Unknown fields are ignored,
but invalid required fields are rejected.

```mbt check
///|
test {
  let policy = policy_from_json(
    (
      #|{
      #|  "roles": { "viewer": ["document:read"] },
      #|  "bindings": [{ "subject": "bob", "role": "viewer" }]
      #|}
    ),
  )
  let decision = policy.authorize(
    Request(subject="bob", action="document:read", resource="document:1"),
  )
  assert_true(decision.allowed)
}
```
