///|
/// Run `moon run --target native cmd/main -- demo` for a self-contained example.
fn main {
  let process_args = @env.args()
  let user_args = [
    for index in 1..<process_args.length() => process_args[index]
  ]
  let exit_code = run_cli(user_args) catch {
    error => {
      println("error: \{to_repr(error)}")
      2
    }
  }
  cli_exit(exit_code)
}

///|
extern "C" fn cli_exit(code : Int) = "exit"

///|
fn run_cli(args : Array[String]) -> Int raise {
  if args.length() == 1 && args[0] == "check" {
    println("usage: moon-policy check POLICY_JSON")
    return 2
  }
  if args.length() == 2 && args[0] == "check" {
    let policy = @policy.policy_from_json(args[1])
    let issues = policy.validate()
    if issues.length() == 0 {
      println("valid")
      return 0
    }
    println("invalid policy")
    return 2
  }
  if args.length() == 3 && args[0] == "eval" {
    let policy = @policy.policy_from_json(args[1])
    let request = @policy.request_from_json(args[2])
    let decision = policy.authorize(request)
    println(decision.to_json().stringify())
    return if decision.allowed { 0 } else { 1 }
  }
  if args.length() == 3 && args[0] == "explain" {
    let policy = @policy.policy_from_json(args[1])
    let request = @policy.request_from_json(args[2])
    let report = policy.explain(request)
    println(report.to_json().stringify())
    return if report.decision.allowed { 0 } else { 1 }
  }
  if args.length() == 4 && args[0] == "diff" {
    let previous = @policy.policy_from_json(args[1])
    let replacement = @policy.policy_from_json(args[2])
    let requests = @policy.requests_from_json(args[3])
    let changes = previous.access_changes(replacement, requests)
    println(
      Json::array([ for change in changes => change.to_json() ]).stringify(),
    )
    return if changes.length() == 0 { 0 } else { 1 }
  }
  if args.length() == 3 && args[0] == "verify" {
    let policy = @policy.policy_from_json(args[1])
    let cases = @policy.cases_from_json(args[2])
    let result = policy.run_cases(cases)
    println(result.to_json().stringify())
    return if result.failed == 0 { 0 } else { 1 }
  }
  if args.length() == 3 && args[0] == "coverage" {
    let policy = @policy.policy_from_json(args[1])
    let requests = @policy.requests_from_json(args[2])
    println(policy.coverage(requests).to_json().stringify())
    return 0
  }
  if args.length() == 1 && args[0] == "demo" {
    let policy = @policy.policy_from_json(
      "{\"roles\":{\"editor\":[\"document:read\"]},\"bindings\":[{\"subject\":\"alice\",\"role\":\"editor\"}]}",
    )
    let request = @policy.request_from_json(
      "{\"subject\":\"alice\",\"action\":\"document:read\",\"resource\":\"document:demo\"}",
    )
    let decision = policy.authorize(request)
    println(decision.to_json().stringify())
    return if decision.allowed { 0 } else { 1 }
  }
  println("usage: moon-policy check POLICY_JSON")
  println("       moon-policy eval POLICY_JSON REQUEST_JSON")
  println("       moon-policy explain POLICY_JSON REQUEST_JSON")
  println(
    "       moon-policy diff OLD_POLICY_JSON NEW_POLICY_JSON REQUESTS_JSON",
  )
  println("       moon-policy verify POLICY_JSON CASES_JSON")
  println("       moon-policy coverage POLICY_JSON REQUESTS_JSON")
  println("       moon-policy demo")
  2
}
