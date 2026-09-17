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

## Scope

The first release provides programmatic RBAC and explicit allow/deny rules.
Attribute-based conditions and CLI tooling are planned next.

Rules can use `Glob("...")` where `*` matches any sequence and `?` matches
one Unicode character. This is useful for HTTP-like resources and namespaced
actions such as `project:read:*`.

Rules may also require scalar attributes under `subject.<key>`,
`resource.<key>`, or `context.<key>`. Missing attributes never satisfy an
`Equals` or `Exists` condition, so evaluation remains fail-closed.
Negating a missing attribute remains unknown rather than becoming true.
An unknown condition never grants access; on a matching deny rule it denies
conservatively.

The JSON format expresses conditions as `exists`, `equals`, `all`, `any`, and
`not` objects. Attribute values can be strings, booleans, or integers.

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
