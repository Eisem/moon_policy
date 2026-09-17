///|
test "role grant allows a matching action" {
  let policy = @moon_policy.Policy(
    role_permissions={ "editor": ["document:read", "document:write"] },
    bindings=[RoleBinding(subject="alice", role="editor")],
  )
  let decision = policy.authorize(
    Request(subject="alice", action="document:write", resource="document:42"),
  )
  assert_true(decision.allowed)
  assert_true(decision.reason is Allowed)
  assert_true(decision.trace == ["role:editor:document:write"])
}

///|
test "policy denies requests without an explicit grant" {
  let decision = @moon_policy.Policy().authorize(
    Request(subject="alice", action="document:read", resource="document:42"),
  )
  assert_true(!decision.allowed)
  assert_true(decision.reason is NoMatchingRule)
  assert_true(decision.trace == [])
}

///|
test "explicit deny overrides a role grant" {
  let policy = @moon_policy.Policy(
    role_permissions={ "admin": ["*"] },
    bindings=[RoleBinding(subject="alice", role="admin")],
    rules=[
      Rule(
        id="locked-documents",
        effect=Deny,
        action=Exact("document:delete"),
        resource=Exact("document:locked"),
      ),
    ],
  )
  let decision = policy.authorize(
    Request(
      subject="alice",
      action="document:delete",
      resource="document:locked",
    ),
  )
  assert_true(!decision.allowed)
  assert_true(decision.reason is ExplicitDeny)
  assert_true(decision.trace == ["role:admin:*", "rule:locked-documents"])
}

///|
test "an explicit allow matches all subjects when subject is omitted" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="public-read",
      effect=Allow,
      action=Exact("document:read"),
      resource=Exact("document:public"),
    ),
  ])
  let decision = policy.authorize(
    Request(
      subject="visitor",
      action="document:read",
      resource="document:public",
    ),
  )
  assert_true(decision.allowed)
  assert_true(decision.reason is Allowed)
  assert_true(decision.trace == ["rule:public-read"])
}

///|
test "glob matchers support HTTP-like resource paths" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="project-read",
      effect=Allow,
      action=Glob("project:read:*"),
      resource=Glob("/projects/*/documents/?"),
    ),
  ])
  let allowed = policy.authorize(
    Request(
      subject="alice",
      action="project:read:metadata",
      resource="/projects/moon-policy/documents/a",
    ),
  )
  let rejected = policy.authorize(
    Request(
      subject="alice",
      action="project:write:metadata",
      resource="/projects/moon-policy/documents/a",
    ),
  )
  assert_true(allowed.allowed)
  assert_true(!rejected.allowed)
}

///|
test "glob matching supports Unicode scalar values" {
  assert_true(@moon_policy.glob_matches("文?", "文档"))
  assert_true(@moon_policy.glob_matches("项目/*", "项目/moon-policy"))
  assert_true(!@moon_policy.glob_matches("文?", "文章库"))
}
