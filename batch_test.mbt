///|
test "batch authorization preserves requests and decision order" {
  let policy = @moon_policy.Policy(rules=[
    Rule(id="read", effect=Allow, action=Exact("read")),
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
  let results = policy.authorize_batch([read, write, read])
  assert_eq(results.length(), 3)
  assert_true(results[0].request == read)
  assert_true(results[0].decision.allowed)
  assert_true(results[1].request == write)
  assert_true(!results[1].decision.allowed)
  assert_true(results[2] == results[0])
  let output = @moon_policy.authorization_results_to_json(results).stringify()
  assert_true(output.contains("\"request\""))
  assert_true(output.contains("\"decision\""))
}

///|
test "empty batch returns an empty JSON array" {
  let results = @moon_policy.Policy().authorize_batch([])
  assert_true(results == [])
  assert_eq(
    @moon_policy.authorization_results_to_json(results).stringify(),
    "[]",
  )
}
