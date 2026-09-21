///|
/// Condition status in a rule inspection. A condition is not evaluated when
/// the rule's subject, action, or resource selector does not match.
pub(all) enum ConditionStatus {
  NotEvaluated
  Satisfied
  Unsatisfied
  Unknown
} derive(Debug, Eq)

///|
/// The selector and condition results for one rule during authorization.
pub(all) struct RuleEvaluation {
  id : String
  effect : Effect
  subject_matches : Bool
  action_matches : Bool
  resource_matches : Bool
  condition_status : ConditionStatus
  applied : Bool
} derive(Debug, Eq)

///|
/// A decision accompanied by an inspection of every explicit rule.
pub(all) struct EvaluationReport {
  decision : Decision
  rules : Array[RuleEvaluation]
} derive(Debug, Eq)

///|
fn condition_status_to_string(status : ConditionStatus) -> String {
  match status {
    NotEvaluated => "not_evaluated"
    Satisfied => "satisfied"
    Unsatisfied => "unsatisfied"
    Unknown => "unknown"
  }
}

///|
fn RuleEvaluation::to_json(self : RuleEvaluation) -> Json {
  Json::object({
    "id": Json::string(self.id),
    "effect": Json::string(
      match self.effect {
        Allow => "allow"
        Deny => "deny"
      },
    ),
    "subject_matches": Json::boolean(self.subject_matches),
    "action_matches": Json::boolean(self.action_matches),
    "resource_matches": Json::boolean(self.resource_matches),
    "condition_status": Json::string(
      condition_status_to_string(self.condition_status),
    ),
    "applied": Json::boolean(self.applied),
  })
}

///|
/// Serialize an explanation as a decision plus ordered rule inspections.
pub fn EvaluationReport::to_json(self : EvaluationReport) -> Json {
  Json::object({
    "decision": self.decision.to_json(),
    "rules": Json::array([ for rule in self.rules => rule.to_json() ]),
  })
}

///|
fn inspect_rule(rule : Rule, request : Request) -> RuleEvaluation {
  let subject_matches = matcher_matches(rule.subject, request.subject)
  let action_matches = matcher_matches(rule.action, request.action)
  let resource_matches = matcher_matches(rule.resource, request.resource)
  let selector_matches = subject_matches && action_matches && resource_matches
  let condition_status = if selector_matches {
    match evaluate_condition(rule.condition, request) {
      ConditionTrue => Satisfied
      ConditionFalse => Unsatisfied
      ConditionUnknown => Unknown
    }
  } else {
    NotEvaluated
  }
  let applied = match (rule.effect, condition_status) {
    (_, Satisfied) => true
    (Deny, Unknown) => true
    _ => false
  }
  {
    id: rule.id,
    effect: rule.effect,
    subject_matches,
    action_matches,
    resource_matches,
    condition_status,
    applied,
  }
}

///|
/// Explain each rule's contribution while preserving `authorize` semantics.
/// Explicit deny rules with an unknown condition are marked as applied because
/// MoonPolicy treats them conservatively after their selectors match.
pub fn Policy::explain(self : Policy, request : Request) -> EvaluationReport {
  let rules : Array[RuleEvaluation] = []
  for rule in self.rules {
    rules.push(inspect_rule(rule, request))
  }
  { decision: self.authorize(request), rules, }
}
