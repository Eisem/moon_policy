///|
test "explanation separates selector mismatch from condition failure" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="wrong-action",
      effect=Allow,
      action=Exact("document:delete"),
      condition=Equals(path="context.team", value=StringValue("platform")),
    ),
    Rule(
      id="wrong-team",
      effect=Allow,
      action=Exact("document:read"),
      condition=Equals(path="context.team", value=StringValue("security")),
    ),
    Rule(
      id="right-team",
      effect=Allow,
      action=Exact("document:read"),
      condition=Equals(path="context.team", value=StringValue("platform")),
    ),
  ])
  let request = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="document:1",
    context={ "team": StringValue("platform") },
  )
  let report = policy.explain(request)
  assert_true(report.decision == policy.authorize(request))
  assert_eq(report.rules.length(), 3)
  assert_true(report.rules[0].condition_status is NotEvaluated)
  assert_true(!report.rules[0].applied)
  assert_true(report.rules[1].condition_status is Unsatisfied)
  assert_true(!report.rules[1].applied)
  assert_true(report.rules[2].condition_status is Satisfied)
  assert_true(report.rules[2].applied)
}

///|
test "explanation exposes conservative deny on unknown condition" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="missing-allow",
      effect=Allow,
      condition=Equals(path="context.verified", value=BoolValue(true)),
    ),
    Rule(
      id="missing-deny",
      effect=Deny,
      condition=Equals(path="context.blocked", value=BoolValue(true)),
    ),
  ])
  let request = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="document:1",
  )
  let report = policy.explain(request)
  assert_true(report.decision.reason is ExplicitDeny)
  assert_true(report.rules[0].condition_status is Unknown)
  assert_true(!report.rules[0].applied)
  assert_true(report.rules[1].condition_status is Unknown)
  assert_true(report.rules[1].applied)
}

///|
test "explanation JSON includes decision and every rule" {
  let policy = @moon_policy.Policy(rules=[
    Rule(id="public", effect=Allow, action=Exact("read")),
  ])
  let request = @moon_policy.Request(
    subject="bob",
    action="read",
    resource="doc:1",
  )
  let output = policy.explain(request).to_json().stringify()
  assert_true(output.contains("\"decision\""))
  assert_true(output.contains("\"condition_status\""))
  assert_true(output.contains("\"public\""))
}
