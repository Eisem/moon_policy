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

The current version provides RBAC, attribute conditions, explicit allow/deny
rules, JSON policy/request parsing, and a native CLI.

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
