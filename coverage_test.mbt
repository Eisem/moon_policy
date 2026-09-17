///|
test "coverage counts selectors, conditions, and final decisions" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="team-read",
      effect=Allow,
      action=Exact("read"),
      condition=Equals(path="context.team", value=StringValue("platform")),
    ),
    Rule(
      id="blocked-document",
      effect=Deny,
      action=Exact("read"),
      resource=Exact("doc:blocked"),
      condition=Equals(path="context.blocked", value=BoolValue(true)),
    ),
    Rule(id="unused-delete", effect=Allow, action=Exact("delete")),
  ])
  let allowed = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:open",
    context={ "team": StringValue("platform"), "blocked": BoolValue(false) },
  )
  let denied = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:blocked",
    context={ "team": StringValue("platform") },
  )
  let wrong_team = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:open",
    context={ "team": StringValue("other") },
  )
  let wrong_action = @moon_policy.Request(
    subject="alice",
    action="write",
    resource="doc:open",
  )
  let coverage = policy.coverage([allowed, denied, wrong_team, wrong_action])
  assert_eq(coverage.total_requests, 4)
  assert_eq(coverage.allowed, 1)
  assert_eq(coverage.explicit_denies, 1)
  assert_eq(coverage.default_denies, 2)
  assert_eq(coverage.rules[0].selector_matches, 3)
  assert_eq(coverage.rules[0].condition_satisfied, 2)
  assert_eq(coverage.rules[0].condition_unsatisfied, 1)
  assert_eq(coverage.rules[0].applied, 2)
  assert_eq(coverage.rules[1].condition_unknown, 1)
  assert_eq(coverage.rules[1].applied, 1)
  assert_true(coverage.uncovered_rule_ids() == ["unused-delete"])
  assert_true(coverage.to_json().stringify().contains("unused-delete"))
}

///|
test "empty corpus reports every rule as uncovered" {
  let policy = @moon_policy.Policy(rules=[
    Rule(id="read", effect=Allow, action=Exact("read")),
    Rule(id="write", effect=Allow, action=Exact("write")),
  ])
  let coverage = policy.coverage([])
  assert_eq(coverage.total_requests, 0)
  assert_true(coverage.uncovered_rule_ids() == ["read", "write"])
}
