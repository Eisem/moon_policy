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
moon run --target native cmd/main -- lint '{"rules":[]}'
moon run --target native cmd/main -- eval '{"rules":[]}' '{"subject":"alice","action":"read","resource":"doc:1"}'
moon run --target native cmd/main -- explain '{"rules":[]}' '{"subject":"alice","action":"read","resource":"doc:1"}'
moon run --target native cmd/main -- diff '{"rules":[]}' '{"rules":[]}' '[{"subject":"alice","action":"read","resource":"doc:1"}]'
moon run --target native cmd/main -- verify '{"rules":[]}' '[{"name":"deny unknown","request":{"subject":"alice","action":"read","resource":"doc:1"},"expected_allowed":false}]'
moon run --target native cmd/main -- coverage '{"rules":[]}' '[{"subject":"alice","action":"read","resource":"doc:1"}]'
```

The CLI exits with 0 for a valid policy or allowed decision, 1 for a denied
decision, and 2 for an invalid command, policy, or request. JSON is passed as
command-line text. The `examples/` directory also contains policy and request
fixtures for integration tests and future file-input support.
For `diff`, exit 0 means no access decisions changed in the supplied request
array; exit 1 means at least one request became allowed or denied. The JSON
output contains only changed decisions, in input order.
For `verify`, exit 0 means all named cases passed; exit 1 means one or more
expectations failed. The JSON output includes every case and aggregate counts.

For exit-code-sensitive automation, run the built native executable directly.
The installed June 2026 `moon run` wrapper returns 0 even when this CLI exits 1.

## Development checks

GitHub Actions checks formatting, generated interfaces, builds, and tests on
the Wasm, Wasm GC, JavaScript, and native backends. Run the same checks locally:

```sh
moon fmt --check
moon info
moon check --target all
moon build --target all
moon test --target all
```

## Scope

The current version provides RBAC with role inheritance, attribute conditions,
explicit allow/deny rules, JSON policy/request parsing, and a native CLI.

Roles can inherit permissions transitively. For example, define
`"role_parents": { "admin": ["editor"] }` alongside `roles` in JSON, or pass
`role_parents={ "admin": ["editor"] }` to `Policy`. Every referenced role must
be declared in `roles`; cycles are rejected during validation. Inherited grants
appear in the decision trace under the role that owns the permission.
Bindings can limit a role grant to a resource: use
`{ "subject": "alice", "role": "editor", "resource": { "glob": "/projects/alpha/*" } }`.
An omitted `resource` matches all resources. Resource scope also applies to
permissions inherited from parent roles.

Rules can use `Glob("...")` where `*` matches any sequence and `?` matches
one Unicode character. This is useful for HTTP-like resources and namespaced
actions such as `project:read:*`.
In JSON, write `{ "glob": "project:read:*" }` in a rule's `action` or
`resource` field; plain JSON strings always mean exact matching.

Rules may also require attributes under `subject.<key>`,
`resource.<key>`, or `context.<key>`. Missing attributes never satisfy an
`Equals` or `Exists` condition, so evaluation remains fail-closed.
Negating a missing attribute remains unknown rather than becoming true.
An unknown condition never grants access; on a matching deny rule it denies
conservatively.
Attribute objects may be nested, so paths such as
`resource.metadata.owner.id` and `context.risk.score` work without flattening
the request. JSON attribute nesting is limited to 16 levels.

The JSON format expresses conditions as `exists`, `equals`, `same`, `one_of`,
`contains`, `compare`, `all`, `any`, and `not` objects. A resource-owner rule can use
`{ "same": { "left": "subject.id", "right": "resource.owner_id" } }`.
Both values must exist and have the same scalar type. Integer thresholds use
`{ "compare": { "path": "context.risk", "op": "lte", "value": 20 } }`;
`op` may be `lt`, `lte`, `gt`, or `gte`. Missing or non-integer attributes are
unknown and never satisfy an allow condition, even under `not`. Attribute
values can be strings, string lists, booleans, or integers.

For group membership, provide a string-list attribute such as
`"subject_attributes": { "groups": ["users", "reviewers"] }` and test it with
`{ "contains": { "path": "subject.groups", "value": "reviewers" } }`.
Missing or non-list attributes remain unknown under `contains` and cannot
become an allow through `not`.
Use `string_matches` with an exact string or `{ "glob": "*@example.com" }` to
match string attributes. Use `contains_any` when one required tag is enough,
and `contains_all` when every listed group, approval, or capability is needed.
Empty required sets are rejected during policy validation.

For an allowlist of regions or teams, use
`{ "one_of": { "path": "context.region", "values": ["eu", "apac"] } }`.
The list must be nonempty and all entries must have the same scalar type.
Call `policy.validate()` for structured configuration diagnostics. JSON loading
rejects invalid policy configuration before returning a policy.

`request_from_json` decodes an authorization request, and `decision.to_json()`
returns `allowed`, `reason`, and the ordered `trace` of matching grants/rules.
`policy.explain(request)` returns the same decision together with an inspection
of every rule's selectors and condition. The CLI `explain` command emits that
report as JSON. Conditions are reported as satisfied, unsatisfied, unknown, or
not evaluated; a matching deny with an unknown condition is marked applied.
`policy.to_json()` exports a programmatically assembled policy in the same
format accepted by `policy_from_json`. Validate a policy before persisting it;
invalid role references, cycles, and malformed conditions are rejected when
loaded again.
`previous.access_changes(replacement, requests)` compares two policies against
a request corpus. It reports newly allowed and newly denied requests, while
ignoring changes that affect only trace text. `requests_from_json` accepts a
JSON array of requests for this workflow.
`cases_from_json` loads named requests with `expected_allowed` booleans, and
`policy.run_cases(cases)` checks them all. See `examples/cases.json` for a
starter policy regression suite.
`policy.coverage(requests)` summarizes allow and deny outcomes plus per-rule
selector, condition, and applied counts. `uncovered_rule_ids()` identifies
rules that the supplied corpus never selected; it does not prove those rules
are unreachable in all possible requests.
`policy.lint()` returns non-blocking warnings for unrestricted allow rules,
wildcard or duplicate role permissions, duplicate parent roles, duplicate rule
bodies, and allow conditions that cannot succeed. `lint` emits the warnings as
JSON; a warning does not make a policy invalid or change its decisions.

## JSON policies

`policy_from_json` loads a constrained JSON format. Unknown policy, binding,
and rule fields are rejected so a misspelled restriction cannot silently
broaden access.

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
