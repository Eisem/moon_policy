///|
test "JSON policy combines role grants and explicit rules" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{
      #|  "roles": { "editor": ["document:read"] },
      #|  "bindings": [{ "subject": "alice", "role": "editor" }],
      #|  "rules": [{
      #|    "id": "locked-documents",
      #|    "effect": "deny",
      #|    "action": "document:delete",
      #|    "resource": "document:locked"
      #|  }]
      #|}
    ),
  )
  let read = policy.authorize(
    Request(subject="alice", action="document:read", resource="document:42"),
  )
  let delete = policy.authorize(
    Request(
      subject="alice",
      action="document:delete",
      resource="document:locked",
    ),
  )
  assert_true(read.allowed)
  assert_true(!delete.allowed)
  assert_true(delete.reason is ExplicitDeny)
}

///|
test "JSON policy rejects unknown effects" {
  try
    ignore(
      @moon_policy.policy_from_json(
        (
          #|{ "rules": [{ "id": "bad", "effect": "maybe" }] }
        ),
      ),
    )
  catch {
    InvalidEffect(effect) => assert_eq(effect, "maybe")
    _ => fail("expected an invalid effect error")
  } noraise {
    _ => fail("expected JSON decoding to fail")
  }
}

///|
test "JSON policy rejects non-string permissions" {
  let source =
    #|{ "roles": { "editor": [1] } }
  try ignore(@moon_policy.policy_from_json(source)) catch {
    ExpectedType(field="roles.editor", expected="string") => ()
    _ => fail("expected a permission type error")
  } noraise {
    _ => fail("expected JSON decoding to fail")
  }
}

///|
test "JSON policy decodes nested attribute conditions" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{
      #|  "rules": [{
      #|    "id": "platform-write",
      #|    "effect": "allow",
      #|    "action": "document:write",
      #|    "condition": {
      #|      "all": [
      #|        { "equals": { "path": "subject.team", "value": "platform" } },
      #|        { "not": { "equals": { "path": "context.blocked", "value": true } } }
      #|      ]
      #|    }
      #|  }]
      #|}
    ),
  )
  let allowed = policy.authorize(
    Request(
      subject="alice",
      action="document:write",
      resource="document:1",
      subject_attributes={ "team": StringValue("platform") },
      context={ "blocked": BoolValue(false) },
    ),
  )
  let blocked = policy.authorize(
    Request(
      subject="alice",
      action="document:write",
      resource="document:1",
      subject_attributes={ "team": StringValue("platform") },
      context={ "blocked": BoolValue(true) },
    ),
  )
  assert_true(allowed.allowed)
  assert_true(!blocked.allowed)
}

///|
test "JSON policy preserves integer attribute values" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{
      #|  "rules": [{
      #|    "id": "minimum-level",
      #|    "effect": "allow",
      #|    "condition": { "equals": { "path": "subject.level", "value": 3 } }
      #|  }]
      #|}
    ),
  )
  let decision = policy.authorize(
    Request(subject="alice", action="document:read", resource="document:1", subject_attributes={
      "level": IntValue(3),
    }),
  )
  assert_true(decision.allowed)
}

///|
test "JSON policy rejects duplicate rule ids" {
  let source =
    #|{ "rules": [
    #|  { "id": "same", "effect": "allow" },
    #|  { "id": "same", "effect": "deny" }
    #|] }
  try ignore(@moon_policy.policy_from_json(source)) catch {
    InvalidPolicy(message) => assert_true(message.contains("duplicate_rule_id"))
    _ => fail("expected an invalid policy error")
  } noraise {
    _ => fail("expected duplicate rule ids to fail")
  }
}

///|
test "JSON condition requires exactly one operator" {
  let source =
    #|{ "rules": [{
    #|  "id": "ambiguous",
    #|  "effect": "allow",
    #|  "condition": { "exists": "subject.team", "not": { "exists": "context.blocked" } }
    #|}] }
  try ignore(@moon_policy.policy_from_json(source)) catch {
    InvalidCondition(_) => ()
    _ => fail("expected an invalid condition error")
  } noraise {
    _ => fail("expected ambiguous condition to fail")
  }
}
