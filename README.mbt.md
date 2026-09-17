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
JSON policy files, attribute-based conditions, and CLI tooling are planned next.
