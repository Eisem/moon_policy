///|
/// How a request corpus exercised one explicit rule.
pub(all) struct RuleCoverage {
  id : String
  selector_matches : Int
  condition_satisfied : Int
  condition_unsatisfied : Int
  condition_unknown : Int
  applied : Int
} derive(Debug, Eq)

///|
/// Aggregate authorization outcomes and per-rule exercise counts.
pub(all) struct PolicyCoverage {
  total_requests : Int
  allowed : Int
  explicit_denies : Int
  default_denies : Int
  rules : Array[RuleCoverage]
} derive(Debug, Eq)

///|
/// Return rule ids that no request matched at the selector level. This is a
/// coverage gap in the supplied corpus, not proof that a rule is unreachable.
pub fn PolicyCoverage::uncovered_rule_ids(
  self : PolicyCoverage,
) -> Array[String] {
  [
    for rule in self.rules if rule.selector_matches == 0 => rule.id
  ]
}

///|
/// Measure how a request corpus exercises the policy. Counts are per request:
/// duplicate requests intentionally count more than once. Rule order is kept.
pub fn Policy::coverage(
  self : Policy,
  requests : Array[Request],
) -> PolicyCoverage {
  let size = self.rules.length()
  let selected = Array::make(size, 0)
  let satisfied = Array::make(size, 0)
  let unsatisfied = Array::make(size, 0)
  let unknown = Array::make(size, 0)
  let applied = Array::make(size, 0)
  let mut allowed = 0
  let mut explicit_denies = 0
  let mut default_denies = 0
  for request in requests {
    let report = self.explain(request)
    match report.decision.reason {
      Allowed => allowed += 1
      ExplicitDeny => explicit_denies += 1
      NoMatchingRule => default_denies += 1
    }
    for index, rule in report.rules {
      match rule.condition_status {
        NotEvaluated => ()
        Satisfied => {
          selected[index] += 1
          satisfied[index] += 1
        }
        Unsatisfied => {
          selected[index] += 1
          unsatisfied[index] += 1
        }
        Unknown => {
          selected[index] += 1
          unknown[index] += 1
        }
      }
      if rule.applied {
        applied[index] += 1
      }
    }
  }
  let rules : Array[RuleCoverage] = []
  for index, rule in self.rules {
    rules.push({
      id: rule.id,
      selector_matches: selected[index],
      condition_satisfied: satisfied[index],
      condition_unsatisfied: unsatisfied[index],
      condition_unknown: unknown[index],
      applied: applied[index],
    })
  }
  {
    total_requests: requests.length(),
    allowed,
    explicit_denies,
    default_denies,
    rules,
  }
}

///|
fn RuleCoverage::to_json(self : RuleCoverage) -> Json {
  Json::object({
    "id": Json::string(self.id),
    "selector_matches": Json::number(Double::from_int(self.selector_matches)),
    "condition_satisfied": Json::number(
      Double::from_int(self.condition_satisfied),
    ),
    "condition_unsatisfied": Json::number(
      Double::from_int(self.condition_unsatisfied),
    ),
    "condition_unknown": Json::number(Double::from_int(self.condition_unknown)),
    "applied": Json::number(Double::from_int(self.applied)),
  })
}

///|
/// Serialize a policy coverage report as machine-readable JSON.
pub fn PolicyCoverage::to_json(self : PolicyCoverage) -> Json {
  Json::object({
    "total_requests": Json::number(Double::from_int(self.total_requests)),
    "allowed": Json::number(Double::from_int(self.allowed)),
    "explicit_denies": Json::number(Double::from_int(self.explicit_denies)),
    "default_denies": Json::number(Double::from_int(self.default_denies)),
    "uncovered_rule_ids": Json::array(
      [
        for id in self.uncovered_rule_ids() => Json::string(id)
      ],
    ),
    "rules": Json::array([ for rule in self.rules => rule.to_json() ]),
  })
}
