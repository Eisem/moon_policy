///|
test "linter detects broad and repeated grants" {
  let policy = @moon_policy.Policy(
    role_permissions={
      "admin": ["*", "document:read", "document:read"],
      "viewer": ["document:read"],
    },
    role_parents={ "admin": ["viewer", "viewer"] },
    rules=[
      Rule(id="allow-everything", effect=Allow),
      Rule(id="same-body", effect=Allow),
    ],
  )
  let warnings = policy.lint()
  let codes = [ for warning in warnings => warning.code ]
  assert_true(codes.contains("wildcard_permission"))
  assert_true(codes.contains("duplicate_permission"))
  assert_true(codes.contains("duplicate_parent"))
  assert_true(codes.contains("unrestricted_allow"))
  assert_true(codes.contains("duplicate_rule_body"))
  assert_true(warnings[0].to_json().stringify().contains("location"))
}

///|
test "linter identifies allow conditions that cannot succeed" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="not-existing",
      effect=Allow,
      condition=Not(Exists("context.token")),
    ),
    Rule(
      id="always-false",
      effect=Allow,
      condition=AllOf([
        Equals(path="context.team", value=StringValue("platform")),
        Not(Always),
      ]),
    ),
    Rule(
      id="any-never-true",
      effect=Allow,
      condition=AnyOf([Not(Always), Not(Exists("context.flag"))]),
    ),
  ])
  let warnings = policy.lint()
  assert_eq(warnings.length(), 3)
  for warning in warnings {
    assert_eq(warning.code, "ineffective_allow")
  }
}

///|
test "linter does not classify a conditional deny as ineffective" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="conservative-deny",
      effect=Deny,
      condition=Not(Exists("context.token")),
    ),
  ])
  assert_true(policy.lint() == [])
  let request = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  assert_true(policy.authorize(request).reason is ExplicitDeny)
}

///|
test "ordinary scoped policy has no warnings" {
  let policy = @moon_policy.Policy(
    role_permissions={ "viewer": ["document:read"] },
    bindings=[
      RoleBinding(subject="alice", role="viewer", resource=Exact("doc:1")),
    ],
    rules=[
      Rule(
        id="owner-write",
        effect=Allow,
        action=Exact("document:write"),
        condition=Same(left="subject.id", right="resource.owner_id"),
      ),
    ],
  )
  assert_true(policy.lint() == [])
}
