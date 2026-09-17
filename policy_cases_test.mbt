///|
test "policy case runner reports all failures in input order" {
  let policy = @moon_policy.Policy(rules=[
    Rule(id="public-read", effect=Allow, action=Exact("read")),
  ])
  let read = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  let write = @moon_policy.Request(
    subject="alice",
    action="write",
    resource="doc:1",
  )
  let cases = [
    @moon_policy.PolicyCase(
      name="read works",
      request=read,
      expected_allowed=true,
    ),
    @moon_policy.PolicyCase(
      name="write denied",
      request=write,
      expected_allowed=false,
    ),
    @moon_policy.PolicyCase(
      name="wrong read expectation",
      request=read,
      expected_allowed=false,
    ),
    @moon_policy.PolicyCase(
      name="wrong write expectation",
      request=write,
      expected_allowed=true,
    ),
  ]
  let result = policy.run_cases(cases)
  assert_eq(result.passed, 2)
  assert_eq(result.failed, 2)
  assert_eq(result.results.length(), 4)
  assert_true(result.results[0].passed)
  assert_true(result.results[1].passed)
  assert_true(!result.results[2].passed)
  assert_true(!result.results[3].passed)
  assert_eq(result.results[2].name, "wrong read expectation")
  assert_true(result.to_json().stringify().contains("wrong write expectation"))
}

///|
test "JSON case set runs against a policy" {
  let source =
    #|[
    #|  {"name":"allow read","request":{"subject":"alice","action":"read","resource":"doc:1"},"expected_allowed":true},
    #|  {"name":"deny write","request":{"subject":"alice","action":"write","resource":"doc:1"},"expected_allowed":false}
    #|]
  let cases = @moon_policy.cases_from_json(source)
  let policy = @moon_policy.Policy(rules=[
    Rule(id="read", effect=Allow, action=Exact("read")),
  ])
  let result = policy.run_cases(cases)
  assert_eq(result.passed, 2)
  assert_eq(result.failed, 0)
}

///|
test "JSON case parser rejects duplicate names" {
  let source =
    #|[
    #|  {"name":"same","request":{"subject":"alice","action":"read","resource":"doc:1"},"expected_allowed":true},
    #|  {"name":"same","request":{"subject":"bob","action":"read","resource":"doc:2"},"expected_allowed":false}
    #|]
  try ignore(@moon_policy.cases_from_json(source)) catch {
    InvalidPolicy(message) =>
      assert_true(message.contains("duplicate case name"))
    _ => fail("expected duplicate case rejection")
  } noraise {
    _ => fail("expected case decoding to fail")
  }
}

///|
test "JSON case parser rejects non-boolean expectations" {
  let source =
    #|[{"name":"wrong type","request":{"subject":"alice","action":"read","resource":"doc:1"},"expected_allowed":"true"}]
  try ignore(@moon_policy.cases_from_json(source)) catch {
    ExpectedType(field="cases[].expected_allowed", expected="boolean") => ()
    _ => fail("expected a boolean type error")
  } noraise {
    _ => fail("expected case decoding to fail")
  }
}

///|
test "empty case suite has zero failures" {
  let cases = @moon_policy.cases_from_json("[]")
  let result = @moon_policy.Policy().run_cases(cases)
  assert_eq(result.passed, 0)
  assert_eq(result.failed, 0)
  assert_true(result.results == [])
}
