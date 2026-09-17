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
test "JSON policy supports inherited roles" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{
      #|  "roles": { "viewer": ["document:read"], "admin": [] },
      #|  "role_parents": { "admin": ["viewer"] },
      #|  "bindings": [{ "subject": "alice", "role": "admin" }]
      #|}
    ),
  )
  let decision = policy.authorize(
    Request(subject="alice", action="document:read", resource="document:1"),
  )
  assert_true(decision.allowed)
  assert_true(decision.trace == ["role:viewer:document:read"])
}

///|
test "JSON policy decodes integer comparisons" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{"rules":[{"id":"threshold","effect":"allow","condition":{"compare":{"path":"context.risk","op":"lte","value":20}}}]}
    ),
  )
  let allowed = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    context={ "risk": IntValue(20) },
  )
  let rejected = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    context={ "risk": IntValue(21) },
  )
  assert_true(policy.authorize(allowed).allowed)
  assert_true(!policy.authorize(rejected).allowed)
}

///|
test "JSON policy supports owner-based rules" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{"rules":[{"id":"owner","effect":"allow","action":"write","condition":{"same":{"left":"subject.id","right":"resource.owner_id"}}}]}
    ),
  )
  let owner = @moon_policy.Request(
    subject="alice",
    action="write",
    resource="doc:1",
    resource_attributes={ "owner_id": StringValue("alice") },
  )
  assert_true(policy.authorize(owner).allowed)
}

///|
test "JSON policy decodes set membership" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{"rules":[{"id":"regions","effect":"allow","condition":{"one_of":{"path":"context.region","values":["eu","apac"]}}}]}
    ),
  )
  let request = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    context={ "region": StringValue("eu") },
  )
  assert_true(policy.authorize(request).allowed)
}

///|
test "JSON policy rejects mixed set element types" {
  let source =
    #|{"rules":[{"id":"mixed","effect":"allow","condition":{"one_of":{"path":"context.region","values":["eu",1]}}}]}
  try ignore(@moon_policy.policy_from_json(source)) catch {
    InvalidPolicy(message) => assert_true(message.contains("mixed_value_types"))
    _ => fail("expected a validation error")
  } noraise {
    _ => fail("expected JSON decoding to fail")
  }
}

///|
test "JSON policy rejects non-integer comparison thresholds" {
  let source =
    #|{"rules":[{"id":"threshold","effect":"allow","condition":{"compare":{"path":"context.risk","op":"lte","value":"20"}}}]}
  try ignore(@moon_policy.policy_from_json(source)) catch {
    ExpectedType(field="rules[].condition.compare.value", expected="integer") =>
      ()
    _ => fail("expected an integer type error")
  } noraise {
    _ => fail("expected decoding to fail")
  }
}

///|
test "JSON policy rejects cyclic role inheritance" {
  let source =
    #|{"roles":{"a":[],"b":[]},"role_parents":{"a":["b"],"b":["a"]}}
  try ignore(@moon_policy.policy_from_json(source)) catch {
    InvalidPolicy(message) =>
      assert_true(message.contains("role_inheritance_cycle"))
    _ => fail("expected a validation error")
  } noraise {
    _ => fail("expected JSON decoding to fail")
  }
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

///|
test "JSON matcher objects support glob patterns" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{
      #|  "rules": [{
      #|    "id": "project-read",
      #|    "effect": "allow",
      #|    "action": { "glob": "project:read:*" },
      #|    "resource": { "glob": "/projects/*/documents/?" }
      #|  }]
      #|}
    ),
  )
  let allowed = policy.authorize(
    Request(
      subject="alice",
      action="project:read:metadata",
      resource="/projects/p1/documents/a",
    ),
  )
  let rejected = policy.authorize(
    Request(
      subject="alice",
      action="project:write:metadata",
      resource="/projects/p1/documents/a",
    ),
  )
  assert_true(allowed.allowed)
  assert_true(!rejected.allowed)
}

///|
test "JSON matcher rejects ambiguous objects" {
  let source =
    #|{ "rules": [{
    #|  "id": "bad",
    #|  "effect": "allow",
    #|  "resource": { "glob": "*", "exact": "admin" }
    #|}] }
  try ignore(@moon_policy.policy_from_json(source)) catch {
    ExpectedType(field="rules[].resource", ..) => ()
    _ => fail("expected an invalid matcher error")
  } noraise {
    _ => fail("expected an ambiguous matcher to fail")
  }
}
