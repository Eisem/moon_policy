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
