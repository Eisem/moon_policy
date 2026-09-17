///|
test "policy JSON roundtrip preserves inherited grants and conditional denies" {
  let original = @moon_policy.Policy(
    role_permissions={
      "viewer": ["document:read"],
      "admin": ["document:delete"],
    },
    role_parents={ "admin": ["viewer"] },
    bindings=[RoleBinding(subject="alice", role="admin")],
    rules=[
      Rule(
        id="restricted-delete",
        effect=Deny,
        subject=Exact("alice"),
        action=Glob("document:*"),
        resource=Glob("document:restricted/*"),
        condition=AllOf([
          Exists("context.request_id"),
          Same(left="subject.id", right="resource.owner_id"),
          Compare(path="context.risk", op=GreaterOrEqual, value=50),
          OneOf(path="context.region", values=[
            StringValue("eu"),
            StringValue("apac"),
          ]),
          Not(Equals(path="context.override", value=BoolValue(true))),
          AnyOf([
            Equals(path="subject.team", value=StringValue("security")),
            Equals(path="subject.team", value=StringValue("operations")),
          ]),
        ]),
      ),
    ],
  )
  let restored = @moon_policy.policy_from_json(original.to_json().stringify())
  let read = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="document:public/1",
  )
  let delete = @moon_policy.Request(
    subject="alice",
    action="document:delete",
    resource="document:restricted/1",
    subject_attributes={ "team": StringValue("security") },
    resource_attributes={ "owner_id": StringValue("alice") },
    context={
      "request_id": StringValue("req-1"),
      "risk": IntValue(50),
      "region": StringValue("eu"),
      "override": BoolValue(false),
    },
  )
  assert_true(original.authorize(read) == restored.authorize(read))
  assert_true(original.authorize(delete) == restored.authorize(delete))
  assert_true(!restored.authorize(delete).allowed)
}

///|
test "default rule JSON roundtrip retains allow and deny semantics" {
  let original = @moon_policy.Policy(rules=[
    Rule(id="public", effect=Allow, action=Exact("read")),
    Rule(id="blocked", effect=Deny, resource=Exact("doc:blocked")),
  ])
  let restored = @moon_policy.policy_from_json(original.to_json().stringify())
  let allowed = @moon_policy.Request(
    subject="bob",
    action="read",
    resource="doc:public",
  )
  let denied = @moon_policy.Request(
    subject="bob",
    action="read",
    resource="doc:blocked",
  )
  assert_true(restored.authorize(allowed).allowed)
  assert_true(restored.authorize(denied).reason is ExplicitDeny)
}
