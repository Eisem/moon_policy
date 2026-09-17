///|
/// A named authorization example with an expected allow or deny result.
pub(all) struct PolicyCase {
  name : String
  request : Request
  expected_allowed : Bool
} derive(Debug, Eq)

///|
pub fn PolicyCase::PolicyCase(
  name~ : String,
  request~ : Request,
  expected_allowed~ : Bool,
) -> PolicyCase {
  { name, request, expected_allowed }
}

///|
/// The actual decision and pass/fail status for a policy case.
pub(all) struct PolicyCaseResult {
  name : String
  request : Request
  expected_allowed : Bool
  decision : Decision
  passed : Bool
} derive(Debug, Eq)

///|
/// Ordered case results and aggregate pass/fail counts.
pub(all) struct PolicySuiteResult {
  results : Array[PolicyCaseResult]
  passed : Int
  failed : Int
} derive(Debug, Eq)

///|
/// Evaluate named examples against a policy. Every case is evaluated even
/// after a failure, so a suite reports all regressions in one run.
pub fn Policy::run_cases(
  self : Policy,
  cases : Array[PolicyCase],
) -> PolicySuiteResult {
  let results : Array[PolicyCaseResult] = []
  let mut passed = 0
  let mut failed = 0
  for case in cases {
    let decision = self.authorize(case.request)
    let success = decision.allowed == case.expected_allowed
    if success {
      passed += 1
    } else {
      failed += 1
    }
    results.push({
      name: case.name,
      request: case.request,
      expected_allowed: case.expected_allowed,
      decision,
      passed: success,
    })
  }
  { results, passed, failed }
}

///|
fn PolicyCaseResult::to_json(self : PolicyCaseResult) -> Json {
  Json::object({
    "name": Json::string(self.name),
    "request": self.request.to_json(),
    "expected_allowed": Json::boolean(self.expected_allowed),
    "decision": self.decision.to_json(),
    "passed": Json::boolean(self.passed),
  })
}

///|
/// Serialize a suite result for CLI and CI consumers.
pub fn PolicySuiteResult::to_json(self : PolicySuiteResult) -> Json {
  Json::object({
    "passed": Json::number(Double::from_int(self.passed)),
    "failed": Json::number(Double::from_int(self.failed)),
    "results": Json::array([ for result in self.results => result.to_json() ]),
  })
}

///|
fn decode_case_expected(value : Json) -> Bool raise PolicyParseError {
  match value {
    True => true
    False => false
    _ =>
      raise ExpectedType(field="cases[].expected_allowed", expected="boolean")
  }
}

///|
/// Decode a JSON array of named authorization examples. Each member requires
/// `name`, `request`, and `expected_allowed` fields; duplicate names fail.
pub fn cases_from_json(
  source : String,
) -> Array[PolicyCase] raise PolicyParseError {
  let root = @json.parse(source) catch {
    error => raise InvalidJson(error.to_string())
  }
  let entries = expect_array(root, field="cases")
  let cases : Array[PolicyCase] = []
  let names : Map[String, Bool] = {}
  for entry in entries {
    let object = expect_object(entry, field="cases[]")
    reject_unknown_fields(
      object,
      ["name", "request", "expected_allowed"],
      "cases[]",
    )
    let name = expect_string(
      required_field(object, "name"),
      field="cases[].name",
    )
    if name == "" {
      raise InvalidPolicy("cases[].name must not be empty")
    }
    if names.contains(name) {
      raise InvalidPolicy("duplicate case name: " + name)
    }
    names[name] = true
    cases.push(
      PolicyCase(
        name~,
        request=decode_request(required_field(object, "request")),
        expected_allowed=decode_case_expected(
          required_field(object, "expected_allowed"),
        ),
      ),
    )
  }
  cases
}
