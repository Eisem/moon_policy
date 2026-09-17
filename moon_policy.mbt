///|
/// An authorization decision effect.
pub(all) enum Effect {
  Allow
  Deny
} derive(Debug, Eq)

///|
/// A matcher for a subject, action, or resource.
pub(all) enum Matcher {
  Any
  Exact(String)
} derive(Debug, Eq)

///|
/// A single explicit policy rule.
pub(all) struct Rule {
  id : String
  effect : Effect
  subject : Matcher
  action : Matcher
  resource : Matcher
} derive(Debug)

///|
/// Create an explicit rule. Omitted matchers match every value.
pub fn Rule::Rule(
  id~ : String,
  effect~ : Effect,
  subject? : Matcher = Any,
  action? : Matcher = Any,
  resource? : Matcher = Any,
) -> Rule {
  { id, effect, subject, action, resource }
}

///|
/// Attach a subject to a named role.
pub(all) struct RoleBinding {
  subject : String
  role : String
} derive(Debug, Eq)

///|
/// Create a role binding.
pub fn RoleBinding::RoleBinding(
  subject~ : String,
  role~ : String,
) -> RoleBinding {
  { subject, role }
}

///|
/// A request passed to the policy evaluator.
pub(all) struct Request {
  subject : String
  action : String
  resource : String
} derive(Debug, Eq)

///|
/// Create an authorization request.
pub fn Request::Request(
  subject~ : String,
  action~ : String,
  resource~ : String,
) -> Request {
  { subject, action, resource }
}

///|
/// Why an authorization request was allowed or denied.
pub(all) enum DecisionReason {
  Allowed
  ExplicitDeny
  NoMatchingRule
} derive(Debug, Eq)

///|
/// The result of evaluating a request. `trace` lists matching rule or role grants.
pub(all) struct Decision {
  allowed : Bool
  reason : DecisionReason
  trace : Array[String]
} derive(Debug, Eq)

///|
/// An immutable policy assembled from role grants, bindings, and explicit rules.
pub(all) struct Policy {
  role_permissions : Map[String, Array[String]]
  bindings : Array[RoleBinding]
  rules : Array[Rule]
} derive(Debug)

///|
/// Create a policy. The evaluator is deny-by-default and explicit denies win.
pub fn Policy::Policy(
  role_permissions? : Map[String, Array[String]] = {},
  bindings? : Array[RoleBinding] = [],
  rules? : Array[Rule] = [],
) -> Policy {
  { role_permissions, bindings, rules }
}

///|
fn matcher_matches(matcher : Matcher, value : String) -> Bool {
  match matcher {
    Any => true
    Exact(expected) => expected == value
  }
}

///|
fn rule_matches(rule : Rule, request : Request) -> Bool {
  matcher_matches(rule.subject, request.subject) &&
  matcher_matches(rule.action, request.action) &&
  matcher_matches(rule.resource, request.resource)
}

///|
fn role_grants(
  policy : Policy,
  request : Request,
  trace : Array[String],
) -> Bool {
  let mut granted = false
  for binding in policy.bindings {
    if binding.subject == request.subject {
      match policy.role_permissions.get(binding.role) {
        Some(permissions) =>
          for permission in permissions {
            if permission == "*" || permission == request.action {
              granted = true
              trace.push("role:" + binding.role + ":" + permission)
            }
          }
        None => ()
      }
    }
  }
  granted
}

///|
/// Evaluate an authorization request.
///
/// Explicit deny rules override every allow rule and role grant. A request with
/// no matching grant is denied.
pub fn Policy::authorize(self : Policy, request : Request) -> Decision {
  let trace : Array[String] = []
  let mut allowed = role_grants(self, request, trace)
  let mut denied = false
  for rule in self.rules {
    if rule_matches(rule, request) {
      trace.push("rule:" + rule.id)
      match rule.effect {
        Allow => allowed = true
        Deny => denied = true
      }
    }
  }
  if denied {
    { allowed: false, reason: ExplicitDeny, trace }
  } else if allowed {
    { allowed: true, reason: Allowed, trace }
  } else {
    { allowed: false, reason: NoMatchingRule, trace }
  }
}
