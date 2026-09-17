///|
test "role bindings grant only within their resource scope" {
  let policy = @moon_policy.Policy(
    role_permissions={ "editor": ["document:write"] },
    bindings=[
      RoleBinding(
        subject="alice",
        role="editor",
        resource=Glob("/projects/alpha/*"),
      ),
    ],
  )
  let inside = @moon_policy.Request(
    subject="alice",
    action="document:write",
    resource="/projects/alpha/documents/1",
  )
  let outside = @moon_policy.Request(
    subject="alice",
    action="document:write",
    resource="/projects/beta/documents/1",
  )
  assert_true(policy.authorize(inside).allowed)
  assert_true(!policy.authorize(outside).allowed)
  assert_true(policy.authorize(outside).trace == [])
}

///|
test "inherited role grants retain binding resource scope" {
  let policy = @moon_policy.Policy(
    role_permissions={ "viewer": ["document:read"], "editor": [] },
    role_parents={ "editor": ["viewer"] },
    bindings=[
      RoleBinding(subject="alice", role="editor", resource=Exact("doc:1")),
    ],
  )
  let inside = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="doc:1",
  )
  let outside = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="doc:2",
  )
  assert_true(policy.authorize(inside).allowed)
  assert_true(!policy.authorize(outside).allowed)
}

///|
test "JSON resource scoped bindings survive serialization" {
  let source =
    #|{"roles":{"editor":["write"]},"bindings":[{"subject":"alice","role":"editor","resource":{"glob":"/alpha/*"}}]}
  let policy = @moon_policy.policy_from_json(source)
  let restored = @moon_policy.policy_from_json(policy.to_json().stringify())
  let inside = @moon_policy.Request(
    subject="alice",
    action="write",
    resource="/alpha/doc:1",
  )
  let outside = @moon_policy.Request(
    subject="alice",
    action="write",
    resource="/beta/doc:1",
  )
  assert_true(restored.authorize(inside).allowed)
  assert_true(!restored.authorize(outside).allowed)
}

///|
test "different resource scopes are distinct role bindings" {
  let policy = @moon_policy.Policy(role_permissions={ "editor": ["write"] }, bindings=[
    RoleBinding(subject="alice", role="editor", resource=Exact("doc:1")),
    RoleBinding(subject="alice", role="editor", resource=Exact("doc:2")),
  ])
  assert_true(policy.validate() == [])
  let duplicate = @moon_policy.Policy(
    role_permissions={ "editor": ["write"] },
    bindings=[
      RoleBinding(subject="alice", role="editor", resource=Exact("doc:1")),
      RoleBinding(subject="alice", role="editor", resource=Exact("doc:1")),
    ],
  )
  assert_eq(duplicate.validate()[0].code, "duplicate_binding")
}
