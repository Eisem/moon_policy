///|
test "nested attributes support ownership and threshold conditions" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="nested-owner",
      effect=Allow,
      action=Exact("document:write"),
      condition=AllOf([
        Same(left="subject.profile.id", right="resource.metadata.owner_id"),
        Compare(path="context.risk.score", op=LessOrEqual, value=20),
      ]),
    ),
  ])
  let allowed = @moon_policy.Request(
    subject="session-user",
    action="document:write",
    resource="document:1",
    subject_attributes={
      "profile": ObjectValue({ "id": StringValue("alice") }),
    },
    resource_attributes={
      "metadata": ObjectValue({ "owner_id": StringValue("alice") }),
    },
    context={ "risk": ObjectValue({ "score": IntValue(20) }) },
  )
  let denied = @moon_policy.Request(
    subject="session-user",
    action="document:write",
    resource="document:1",
    subject_attributes={ "profile": ObjectValue({ "id": StringValue("bob") }) },
    resource_attributes={
      "metadata": ObjectValue({ "owner_id": StringValue("alice") }),
    },
    context={ "risk": ObjectValue({ "score": IntValue(20) }) },
  )
  assert_true(policy.authorize(allowed).allowed)
  assert_true(!policy.authorize(denied).allowed)
}

///|
test "nested missing and non-object segments stay unknown" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="not-blocked",
      effect=Allow,
      condition=Not(
        Equals(path="context.security.blocked", value=BoolValue(true)),
      ),
    ),
  ])
  let missing = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  let scalar_parent = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    context={ "security": StringValue("clear") },
  )
  let present = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    context={ "security": ObjectValue({ "blocked": BoolValue(false) }) },
  )
  assert_true(!policy.authorize(missing).allowed)
  assert_true(!policy.authorize(scalar_parent).allowed)
  assert_true(policy.authorize(present).allowed)
}

///|
test "nested JSON attributes roundtrip through requests" {
  let source =
    #|{"subject":"alice","action":"read","resource":"doc:1","resource_attributes":{"metadata":{"owner":{"id":"alice"},"tags":["public","reviewed"]}},"context":{"risk":{"score":7}}}
  let request = @moon_policy.request_from_json(source)
  let restored = @moon_policy.request_from_json(request.to_json().stringify())
  assert_true(restored == request)
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="nested-json",
      effect=Allow,
      condition=AllOf([
        Same(left="subject.id", right="resource.metadata.owner.id"),
        Contains(path="resource.metadata.tags", value="reviewed"),
        Compare(path="context.risk.score", op=LessThan, value=10),
      ]),
    ),
  ])
  assert_true(policy.authorize(restored).allowed)
}

///|
test "validation accepts nested paths and rejects empty segments" {
  let valid = @moon_policy.Policy(rules=[
    Rule(
      id="valid-nested",
      effect=Allow,
      condition=Exists("resource.metadata.owner.id"),
    ),
  ])
  assert_true(valid.validate() == [])
  let invalid = @moon_policy.Policy(rules=[
    Rule(
      id="invalid-nested",
      effect=Allow,
      condition=Equals(path="resource.metadata..id", value=StringValue("alice")),
    ),
  ])
  assert_eq(invalid.validate()[0].code, "invalid_attribute_path")
}

///|
test "JSON parser rejects excessive attribute nesting" {
  let source =
    #|{"subject":"alice","action":"read","resource":"doc:1","context":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":{"r":1}}}}}}}}}}}}}}}}}}}
  try ignore(@moon_policy.request_from_json(source)) catch {
    InvalidPolicy(message) =>
      assert_true(message.contains("nesting exceeds 16"))
    _ => fail("expected nesting limit error")
  } noraise {
    _ => fail("expected request decoding to fail")
  }
}
