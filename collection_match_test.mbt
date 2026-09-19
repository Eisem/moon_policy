///|
test "string matcher supports exact and glob attributes" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="company-email",
      effect=Allow,
      action=Exact("account:login"),
      condition=AllOf([
        StringMatches(path="subject.email", matcher=Glob("*@example.com")),
        StringMatches(path="context.environment", matcher=Exact("production")),
      ]),
    ),
  ])
  let employee = @moon_policy.Request(
    subject="alice",
    action="account:login",
    resource="account:alice",
    subject_attributes={ "email": StringValue("alice@example.com") },
    context={ "environment": StringValue("production") },
  )
  let external = @moon_policy.Request(
    subject="bob",
    action="account:login",
    resource="account:bob",
    subject_attributes={ "email": StringValue("bob@external.test") },
    context={ "environment": StringValue("production") },
  )
  assert_true(policy.authorize(employee).allowed)
  assert_true(!policy.authorize(external).allowed)
}

///|
test "string matcher treats missing and non-string attributes as unknown" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="not-service-account",
      effect=Allow,
      condition=Not(
        StringMatches(
          path="subject.email",
          matcher=Glob("service-*@example.com"),
        ),
      ),
    ),
  ])
  let missing = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  let wrong_type = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    subject_attributes={ "email": StringListValue(["alice@example.com"]) },
  )
  let person = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    subject_attributes={ "email": StringValue("alice@example.com") },
  )
  assert_true(!policy.authorize(missing).allowed)
  assert_true(!policy.authorize(wrong_type).allowed)
  assert_true(policy.authorize(person).allowed)
}

///|
test "contains any and all express tag requirements" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="deploy",
      effect=Allow,
      action=Exact("service:deploy"),
      condition=AllOf([
        ContainsAny(path="subject.groups", values=[
          "release-managers", "administrators",
        ]),
        ContainsAll(path="context.approvals", values=["security", "operations"]),
      ]),
    ),
  ])
  let approved = @moon_policy.Request(
    subject="alice",
    action="service:deploy",
    resource="service:payments",
    subject_attributes={
      "groups": StringListValue(["engineers", "release-managers"]),
    },
    context={
      "approvals": StringListValue(["operations", "security", "owner"]),
    },
  )
  let incomplete = @moon_policy.Request(
    subject="alice",
    action="service:deploy",
    resource="service:payments",
    subject_attributes={ "groups": StringListValue(["administrators"]) },
    context={ "approvals": StringListValue(["security"]) },
  )
  assert_true(policy.authorize(approved).allowed)
  assert_true(!policy.authorize(incomplete).allowed)
}

///|
test "JSON collection conditions survive policy roundtrip" {
  let source =
    #|{"rules":[{"id":"release","effect":"allow","condition":{"all":[{"string_matches":{"path":"subject.email","matcher":{"glob":"*@example.com"}}},{"contains_any":{"path":"subject.groups","values":["release","admin"]}},{"contains_all":{"path":"context.approvals","values":["security","owner"]}}]}}]}
  let policy = @moon_policy.policy_from_json(source)
  let restored = @moon_policy.policy_from_json(policy.to_json().stringify())
  let request = @moon_policy.Request(
    subject="alice",
    action="deploy",
    resource="service:1",
    subject_attributes={
      "email": StringValue("alice@example.com"),
      "groups": StringListValue(["release"]),
    },
    context={ "approvals": StringListValue(["owner", "security"]) },
  )
  assert_true(policy.authorize(request).allowed)
  assert_true(restored.authorize(request) == policy.authorize(request))
}

///|
test "validation rejects empty collection requirements" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="empty-any",
      effect=Allow,
      condition=ContainsAny(path="subject.groups", values=[]),
    ),
    Rule(
      id="empty-all",
      effect=Allow,
      condition=ContainsAll(path="subject.groups", values=[]),
    ),
  ])
  let issues = policy.validate()
  assert_eq(issues.length(), 2)
  assert_eq(issues[0].code, "empty_string_set")
  assert_eq(issues[1].code, "empty_string_set")
  let source =
    #|{"rules":[{"id":"bad","effect":"allow","condition":{"contains_any":{"path":"subject.groups","values":[]}}}]}
  try ignore(@moon_policy.policy_from_json(source)) catch {
    InvalidPolicy(message) => assert_true(message.contains("empty_string_set"))
    _ => fail("expected policy validation error")
  } noraise {
    _ => fail("expected JSON policy loading to fail")
  }
}

///|
test "JSON collection conditions require string elements" {
  let source =
    #|{"rules":[{"id":"bad","effect":"allow","condition":{"contains_all":{"path":"subject.groups","values":["admin",1]}}}]}
  try ignore(@moon_policy.policy_from_json(source)) catch {
    ExpectedType(
      field="rules[].condition.contains_all.values[]",
      expected="string"
    ) => ()
    _ => fail("expected string element error")
  } noraise {
    _ => fail("expected condition decoding to fail")
  }
}
