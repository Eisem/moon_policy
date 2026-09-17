///|
test "JSON request attributes drive policy evaluation" {
  let policy = @moon_policy.policy_from_json(
    (
      #|{
      #|  "rules": [{
      #|    "id": "team-read",
      #|    "effect": "allow",
      #|    "action": "document:read",
      #|    "condition": { "equals": { "path": "subject.team", "value": "platform" } }
      #|  }]
      #|}
    ),
  )
  let request = @moon_policy.request_from_json(
    (
      #|{
      #|  "subject": "alice",
      #|  "action": "document:read",
      #|  "resource": "document:42",
      #|  "subject_attributes": { "team": "platform" }
      #|}
    ),
  )
  let decision = policy.authorize(request)
  json_inspect(decision.to_json(), content={
    "allowed": true,
    "reason": "allowed",
    "trace": ["rule:team-read"],
  })
}

///|
test "JSON request rejects missing mandatory fields" {
  let source =
    #|{ "subject": "alice", "action": "document:read" }
  try ignore(@moon_policy.request_from_json(source)) catch {
    MissingField("resource") => ()
    _ => fail("expected a missing resource error")
  } noraise {
    _ => fail("expected an invalid request")
  }
}

///|
test "JSON request rejects unsupported attribute types" {
  let source =
    #|{
    #|  "subject": "alice",
    #|  "action": "document:read",
    #|  "resource": "document:42",
    #|  "context": { "roles": { "admin": true } }
    #|}
  try ignore(@moon_policy.request_from_json(source)) catch {
    ExpectedType(field="context.roles", ..) => ()
    _ => fail("expected an attribute type error")
  } noraise {
    _ => fail("expected an invalid request")
  }
}
