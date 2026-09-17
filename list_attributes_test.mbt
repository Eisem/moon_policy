///|
test "contains checks membership in a subject group list" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="reviewers",
      effect=Allow,
      action=Exact("review:approve"),
      condition=Contains(path="subject.groups", value="reviewers"),
    ),
  ])
  let group_member = @moon_policy.Request(
    subject="alice",
    action="review:approve",
    resource="review:1",
    subject_attributes={ "groups": StringListValue(["engineers", "reviewers"]) },
  )
  let nonmember = @moon_policy.Request(
    subject="bob",
    action="review:approve",
    resource="review:1",
    subject_attributes={ "groups": StringListValue(["engineers"]) },
  )
  assert_true(policy.authorize(group_member).allowed)
  assert_true(!policy.authorize(nonmember).allowed)
}

///|
test "missing or mistyped list is unknown under negation" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="not-admin",
      effect=Allow,
      condition=Not(Contains(path="subject.groups", value="admins")),
    ),
  ])
  let missing = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  let scalar = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    subject_attributes={ "groups": StringValue("users") },
  )
  let empty_list = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    subject_attributes={ "groups": StringListValue([]) },
  )
  assert_true(!policy.authorize(missing).allowed)
  assert_true(!policy.authorize(scalar).allowed)
  assert_true(policy.authorize(empty_list).allowed)
}

///|
test "JSON list attributes and contains condition roundtrip" {
  let source =
    #|{"rules":[{"id":"admins","effect":"allow","condition":{"contains":{"path":"subject.groups","value":"admins"}}}]}
  let policy = @moon_policy.policy_from_json(source)
  let restored = @moon_policy.policy_from_json(policy.to_json().stringify())
  let request = @moon_policy.request_from_json(
    (
      #|{"subject":"alice","action":"read","resource":"doc:1","subject_attributes":{"groups":["users","admins"]}}
    ),
  )
  assert_true(restored.authorize(request).allowed)
  let request_roundtrip = @moon_policy.request_from_json(
    request.to_json().stringify(),
  )
  assert_true(request_roundtrip == request)
}

///|
test "JSON list attributes reject non-string elements" {
  let source =
    #|{"subject":"alice","action":"read","resource":"doc:1","subject_attributes":{"groups":["admins",1]}}
  try ignore(@moon_policy.request_from_json(source)) catch {
    ExpectedType(field="subject_attributes.groups[]", expected="string") => ()
    _ => fail("expected a string element error")
  } noraise {
    _ => fail("expected request decoding to fail")
  }
}
