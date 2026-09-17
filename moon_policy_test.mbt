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
test "role inheritance grants transitive permissions once" {
  let policy = @moon_policy.Policy(
    role_permissions={
      "viewer": ["document:read"],
      "editor": ["document:write"],
      "admin": [],
    },
    role_parents={ "admin": ["editor", "viewer"], "editor": ["viewer"] },
    bindings=[RoleBinding(subject="alice", role="admin")],
  )
  let decision = policy.authorize(
    Request(subject="alice", action="document:read", resource="document:1"),
  )
  assert_true(decision.allowed)
  assert_true(decision.trace == ["role:viewer:document:read"])
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

///|
test "glob matching handles dense wildcard patterns" {
  let pattern = "*a*a*a*a*a*a*a*a*a*a*z"
  let value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaz"
  assert_true(@moon_policy.glob_matches(pattern, value))
  assert_true(!@moon_policy.glob_matches(pattern, value + "x"))
  assert_true(@moon_policy.glob_matches("", ""))
  assert_true(!@moon_policy.glob_matches("", "x"))
  assert_true(@moon_policy.glob_matches("*", ""))
}

///|
test "attribute conditions can protect a resource owner" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="owner-write",
      effect=Allow,
      action=Exact("document:write"),
      condition=Equals(path="subject.team", value=StringValue("platform")),
    ),
  ])
  let platform_request = @moon_policy.Request(
    subject="alice",
    action="document:write",
    resource="document:42",
    subject_attributes={ "team": StringValue("platform") },
  )
  let other_request = @moon_policy.Request(
    subject="bob",
    action="document:write",
    resource="document:42",
    subject_attributes={ "team": StringValue("product") },
  )
  assert_true(policy.authorize(platform_request).allowed)
  assert_true(!policy.authorize(other_request).allowed)
}

///|
test "integer comparisons enforce inclusive and exclusive thresholds" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="low-risk",
      effect=Allow,
      action=Exact("payment:approve"),
      condition=AllOf([
        Compare(path="context.risk", op=GreaterOrEqual, value=0),
        Compare(path="context.risk", op=LessThan, value=50),
      ]),
    ),
  ])
  for risk in [0, 49] {
    let request = @moon_policy.Request(
      subject="alice",
      action="payment:approve",
      resource="payment:1",
      context={ "risk": IntValue(risk) },
    )
    assert_true(policy.authorize(request).allowed)
  }
  for risk in [-1, 50] {
    let request = @moon_policy.Request(
      subject="alice",
      action="payment:approve",
      resource="payment:1",
      context={ "risk": IntValue(risk) },
    )
    assert_true(!policy.authorize(request).allowed)
  }
}

///|
test "attribute equality supports resource ownership" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="owner-update",
      effect=Allow,
      action=Exact("document:update"),
      condition=Same(left="subject.id", right="resource.owner_id"),
    ),
  ])
  let owner = @moon_policy.Request(
    subject="alice",
    action="document:update",
    resource="document:1",
    resource_attributes={ "owner_id": StringValue("alice") },
  )
  let stranger = @moon_policy.Request(
    subject="bob",
    action="document:update",
    resource="document:1",
    resource_attributes={ "owner_id": StringValue("alice") },
  )
  assert_true(policy.authorize(owner).allowed)
  assert_true(!policy.authorize(stranger).allowed)
}

///|
test "attribute equality cannot grant on absent or incompatible values" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="matching-teams",
      effect=Allow,
      condition=Same(left="subject.team", right="resource.team"),
    ),
  ])
  let missing = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  let mistyped = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    subject_attributes={ "team": StringValue("42") },
    resource_attributes={ "team": IntValue(42) },
  )
  assert_true(!policy.authorize(missing).allowed)
  assert_true(!policy.authorize(mistyped).allowed)
}

///|
test "integer comparison with missing or mistyped attribute is unknown" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="not-high-risk",
      effect=Allow,
      condition=Not(Compare(path="context.risk", op=GreaterThan, value=50)),
    ),
  ])
  let missing = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  let mistyped = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
    context={ "risk": StringValue("low") },
  )
  assert_true(!policy.authorize(missing).allowed)
  assert_true(!policy.authorize(mistyped).allowed)
}

///|
test "composite conditions fail closed when an attribute is absent" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="office-hours-admin",
      effect=Allow,
      action=Exact("admin:read"),
      condition=AllOf([
        Exists("context.request_id"),
        AnyOf([
          Equals(path="subject.role", value=StringValue("operator")),
          Equals(path="subject.role", value=StringValue("admin")),
        ]),
        Not(Equals(path="context.blocked", value=BoolValue(true))),
      ]),
    ),
  ])
  let valid = @moon_policy.Request(
    subject="alice",
    action="admin:read",
    resource="admin:reports",
    subject_attributes={ "role": StringValue("operator") },
    context={ "request_id": StringValue("req-1"), "blocked": BoolValue(false) },
  )
  let missing_context = @moon_policy.Request(
    subject="alice",
    action="admin:read",
    resource="admin:reports",
    subject_attributes={ "role": StringValue("operator") },
  )
  assert_true(policy.authorize(valid).allowed)
  assert_true(!policy.authorize(missing_context).allowed)
}

///|
test "negating a missing attribute does not grant access" {
  let policy = @moon_policy.Policy(rules=[
    Rule(
      id="not-blocked",
      effect=Allow,
      condition=Not(Equals(path="context.blocked", value=BoolValue(true))),
    ),
  ])
  let missing = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="document:1",
  )
  let present = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="document:1",
    context={ "blocked": BoolValue(false) },
  )
  assert_true(!policy.authorize(missing).allowed)
  assert_true(policy.authorize(present).allowed)
}

///|
test "uncertain deny condition overrides a role grant" {
  let policy = @moon_policy.Policy(
    role_permissions={ "reader": ["document:read"] },
    bindings=[RoleBinding(subject="alice", role="reader")],
    rules=[
      Rule(
        id="requires-clearance",
        effect=Deny,
        condition=Not(Equals(path="subject.clearance", value=StringValue("ok"))),
      ),
    ],
  )
  let request = @moon_policy.Request(
    subject="alice",
    action="document:read",
    resource="document:1",
  )
  let decision = policy.authorize(request)
  assert_true(!decision.allowed)
  assert_true(decision.reason is ExplicitDeny)
}
