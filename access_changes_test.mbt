///|
test "policy diff reports newly allowed and denied requests in corpus order" {
  let previous = @moon_policy.Policy(rules=[
    Rule(
      id="old-document",
      effect=Allow,
      action=Exact("read"),
      resource=Exact("doc:old"),
    ),
  ])
  let replacement = @moon_policy.Policy(rules=[
    Rule(
      id="new-document",
      effect=Allow,
      action=Exact("read"),
      resource=Exact("doc:new"),
    ),
  ])
  let old_request = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:old",
  )
  let unchanged_request = @moon_policy.Request(
    subject="alice",
    action="write",
    resource="doc:other",
  )
  let new_request = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:new",
  )
  let changes = previous.access_changes(replacement, [
    old_request, unchanged_request, new_request,
  ])
  assert_eq(changes.length(), 2)
  assert_true(changes[0].request == old_request)
  assert_true(changes[0].kind() is NewlyDenied)
  assert_true(changes[1].request == new_request)
  assert_true(changes[1].kind() is NewlyAllowed)
  let output = changes[1].to_json().stringify()
  assert_true(output.contains("newly_allowed"))
  assert_true(output.contains("doc:new"))
}

///|
test "policy diff ignores trace-only changes" {
  let previous = @moon_policy.Policy(rules=[
    Rule(id="first-name", effect=Allow, action=Exact("read")),
  ])
  let replacement = @moon_policy.Policy(rules=[
    Rule(id="renamed-rule", effect=Allow, action=Exact("read")),
  ])
  let request = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc:1",
  )
  assert_true(
    previous.authorize(request).trace != replacement.authorize(request).trace,
  )
  assert_true(previous.access_changes(replacement, [request]) == [])
}

///|
test "request array JSON and request serialization roundtrip" {
  let requests = @moon_policy.requests_from_json(
    (
      #|[
      #|  {"subject":"alice","action":"read","resource":"doc:1","context":{"risk":5}},
      #|  {"subject":"bob","action":"write","resource":"doc:2","subject_attributes":{"verified":true}}
      #|]
    ),
  )
  assert_eq(requests.length(), 2)
  for request in requests {
    let restored = @moon_policy.request_from_json(request.to_json().stringify())
    assert_true(restored == request)
  }
}

///|
test "request array parser rejects malformed member" {
  let source =
    #|[{"subject":"alice","action":"read","resource":"doc:1"},{"subject":"bob","resource":"doc:2"}]
  try ignore(@moon_policy.requests_from_json(source)) catch {
    MissingField("action") => ()
    _ => fail("expected a missing action error")
  } noraise {
    _ => fail("expected request array decoding to fail")
  }
}
