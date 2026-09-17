///|
test "policy validation catches unknown role and duplicate rule id" {
  let policy = @moon_policy.Policy(
    bindings=[RoleBinding(subject="alice", role="missing")],
    rules=[Rule(id="same", effect=Allow), Rule(id="same", effect=Deny)],
  )
  let issues = policy.validate()
  assert_eq(issues.length(), 2)
  assert_eq(issues[0].code, "unknown_role")
  assert_eq(issues[1].code, "duplicate_rule_id")
}

///|
test "policy validation rejects malformed attribute paths and empty groups" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="bad",
      effect=Allow,
      condition=AllOf([Exists("unknown.team"), AnyOf([])]),
    ),
  ])
  let issues = policy.validate()
  assert_eq(issues.length(), 2)
  assert_eq(issues[0].code, "invalid_attribute_path")
  assert_eq(issues[1].code, "empty_condition_group")
}

///|
test "a valid policy has no diagnostics" {
  let policy = @moon_policy.Policy(
    role_permissions={ "viewer": ["document:read"] },
    bindings=[RoleBinding(subject="alice", role="viewer")],
    rules=[
      Rule(
        id="blocked",
        effect=Deny,
        condition=Equals(path="context.blocked", value=BoolValue(true)),
      ),
    ],
  )
  assert_true(policy.validate() == [])
}

///|
test "role inheritance rejects unknown parent and cycles" {
  let unknown = @moon_policy.Policy(role_permissions={ "admin": [] }, role_parents={
    "admin": ["missing"],
  })
  assert_eq(unknown.validate()[0].code, "unknown_parent_role")
  let cyclic = @moon_policy.Policy(
    role_permissions={ "admin": [], "editor": [] },
    role_parents={ "admin": ["editor"], "editor": ["admin"] },
  )
  assert_eq(cyclic.validate()[0].code, "role_inheritance_cycle")
}

///|
test "validation checks both attribute comparison paths" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="bad-same",
      effect=Allow,
      condition=Same(left="bad.id", right="resource."),
    ),
  ])
  let issues = policy.validate()
  assert_eq(issues.length(), 2)
  assert_eq(issues[0].location, "rules.0.condition.left")
  assert_eq(issues[1].location, "rules.0.condition.right")
}

///|
test "validation rejects empty membership sets" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="empty-set",
      effect=Allow,
      condition=OneOf(path="context.region", values=[]),
    ),
  ])
  assert_eq(policy.validate()[0].code, "empty_value_set")
}
