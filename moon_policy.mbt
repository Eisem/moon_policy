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
  Glob(String)
} derive(Debug, Eq)

///|
/// An attribute supplied by the caller for attribute-based authorization.
pub(all) enum AttributeValue {
  StringValue(String)
  StringListValue(Array[String])
  BoolValue(Bool)
  IntValue(Int)
} derive(Debug, Eq)

///|
/// An integer threshold comparison for an attribute condition.
pub(all) enum Comparison {
  LessThan
  LessOrEqual
  GreaterThan
  GreaterOrEqual
} derive(Debug, Eq)

///|
/// A condition attached to an explicit rule.
pub(all) enum Condition {
  Always
  Exists(String)
  Equals(path~ : String, value~ : AttributeValue)
  Same(left~ : String, right~ : String)
  OneOf(path~ : String, values~ : Array[AttributeValue])
  Contains(path~ : String, value~ : String)
  Compare(path~ : String, op~ : Comparison, value~ : Int)
  AllOf(Array[Condition])
  AnyOf(Array[Condition])
  Not(Condition)
} derive(Debug, Eq)

///|
/// A single explicit policy rule.
pub(all) struct Rule {
  id : String
  effect : Effect
  subject : Matcher
  action : Matcher
  resource : Matcher
  condition : Condition
} derive(Debug)

///|
/// Create an explicit rule. Omitted matchers match every value.
pub fn Rule::Rule(
  id~ : String,
  effect~ : Effect,
  subject? : Matcher = Any,
  action? : Matcher = Any,
  resource? : Matcher = Any,
  condition? : Condition = Always,
) -> Rule {
  { id, effect, subject, action, resource, condition }
}

///|
/// Attach a subject to a named role.
pub(all) struct RoleBinding {
  subject : String
  role : String
  resource : Matcher
} derive(Debug, Eq)

///|
/// Create a role binding.
pub fn RoleBinding::RoleBinding(
  subject~ : String,
  role~ : String,
  resource? : Matcher = Any,
) -> RoleBinding {
  { subject, role, resource }
}

///|
/// A request passed to the policy evaluator.
pub(all) struct Request {
  subject : String
  action : String
  resource : String
  subject_attributes : Map[String, AttributeValue]
  resource_attributes : Map[String, AttributeValue]
  context : Map[String, AttributeValue]
} derive(Debug, Eq)

///|
/// Create an authorization request.
pub fn Request::Request(
  subject~ : String,
  action~ : String,
  resource~ : String,
  subject_attributes? : Map[String, AttributeValue] = {},
  resource_attributes? : Map[String, AttributeValue] = {},
  context? : Map[String, AttributeValue] = {},
) -> Request {
  {
    subject,
    action,
    resource,
    subject_attributes,
    resource_attributes,
    context,
  }
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
  role_parents : Map[String, Array[String]]
  bindings : Array[RoleBinding]
  rules : Array[Rule]
} derive(Debug)

///|
/// Create a policy. The evaluator is deny-by-default and explicit denies win.
pub fn Policy::Policy(
  role_permissions? : Map[String, Array[String]] = {},
  role_parents? : Map[String, Array[String]] = {},
  bindings? : Array[RoleBinding] = [],
  rules? : Array[Rule] = [],
) -> Policy {
  { role_permissions, role_parents, bindings, rules }
}

///|
fn matcher_matches(matcher : Matcher, value : String) -> Bool {
  match matcher {
    Any => true
    Exact(expected) => expected == value
    Glob(pattern) => glob_matches(pattern, value)
  }
}

///|
/// Match a value against a glob pattern. `*` matches zero or more characters
/// and `?` matches exactly one Unicode scalar value. Runtime is bounded by
/// O(pattern length * value length) with O(value length) working memory.
pub fn glob_matches(pattern : String, value : String) -> Bool {
  let pattern_chars : Array[Char] = [ for character in pattern => character ]
  let value_chars : Array[Char] = [ for character in value => character ]
  let pattern_length = pattern_chars.length()
  let value_length = value_chars.length()
  let mut next = Array::make(value_length + 1, false)
  next[value_length] = true
  for pattern_offset in 0..<pattern_length {
    let pattern_index = pattern_length - 1 - pattern_offset
    let current = Array::make(value_length + 1, false)
    for value_offset in 0..<=value_length {
      let value_index = value_length - value_offset
      current[value_index] = match pattern_chars[pattern_index] {
        '*' =>
          next[value_index] ||
          (value_index < value_length && current[value_index + 1])
        '?' => value_index < value_length && next[value_index + 1]
        character =>
          value_index < value_length &&
          value_chars[value_index] == character &&
          next[value_index + 1]
      }
    }
    next = current
  }
  next[0]
}

///|
fn rule_matches(rule : Rule, request : Request) -> Bool {
  if !(matcher_matches(rule.subject, request.subject) &&
    matcher_matches(rule.action, request.action) &&
    matcher_matches(rule.resource, request.resource)) {
    return false
  }
  match (rule.effect, evaluate_condition(rule.condition, request)) {
    (_, ConditionTrue) => true
    (Deny, ConditionUnknown) => true
    _ => false
  }
}

///|
priv enum ConditionResult {
  ConditionTrue
  ConditionFalse
  ConditionUnknown
}

///|
fn resolve_attribute(request : Request, path : String) -> AttributeValue? {
  let parts = path.split(".").to_array()
  if parts.length() != 2 {
    return None
  }
  match (parts[0], parts[1]) {
    ("subject", "id") => Some(StringValue(request.subject))
    ("resource", "id") => Some(StringValue(request.resource))
    ("subject", key) => request.subject_attributes.get(key.to_owned())
    ("resource", key) => request.resource_attributes.get(key.to_owned())
    ("context", key) => request.context.get(key.to_owned())
    _ => None
  }
}

///|
fn evaluate_condition(
  condition : Condition,
  request : Request,
) -> ConditionResult {
  match condition {
    Always => ConditionTrue
    Exists(path) =>
      if resolve_attribute(request, path) is Some(_) {
        ConditionTrue
      } else {
        ConditionUnknown
      }
    Equals(path~, value~) =>
      match resolve_attribute(request, path) {
        None => ConditionUnknown
        Some(actual) =>
          if actual == value {
            ConditionTrue
          } else {
            match (actual, value) {
              (StringValue(_), StringValue(_))
              | (StringListValue(_), StringListValue(_))
              | (BoolValue(_), BoolValue(_))
              | (IntValue(_), IntValue(_)) => ConditionFalse
              _ => ConditionUnknown
            }
          }
      }
    Same(left~, right~) =>
      match
        (resolve_attribute(request, left), resolve_attribute(request, right)) {
        (Some(left_value), Some(right_value)) =>
          if left_value == right_value {
            ConditionTrue
          } else {
            match (left_value, right_value) {
              (StringValue(_), StringValue(_))
              | (StringListValue(_), StringListValue(_))
              | (BoolValue(_), BoolValue(_))
              | (IntValue(_), IntValue(_)) => ConditionFalse
              _ => ConditionUnknown
            }
          }
        _ => ConditionUnknown
      }
    OneOf(path~, values~) =>
      match resolve_attribute(request, path) {
        None => ConditionUnknown
        Some(actual) => {
          let mut same_type = false
          for value in values {
            if actual == value {
              return ConditionTrue
            }
            match (actual, value) {
              (StringValue(_), StringValue(_))
              | (StringListValue(_), StringListValue(_))
              | (BoolValue(_), BoolValue(_))
              | (IntValue(_), IntValue(_)) => same_type = true
              _ => ()
            }
          }
          if same_type {
            ConditionFalse
          } else {
            ConditionUnknown
          }
        }
      }
    Contains(path~, value~) =>
      match resolve_attribute(request, path) {
        None => ConditionUnknown
        Some(StringListValue(values)) => {
          let mut found = false
          for item in values {
            if item == value {
              found = true
              break
            }
          }
          if found {
            ConditionTrue
          } else {
            ConditionFalse
          }
        }
        Some(_) => ConditionUnknown
      }
    Compare(path~, op~, value~) =>
      match resolve_attribute(request, path) {
        None => ConditionUnknown
        Some(IntValue(actual)) => {
          let matched = match op {
            LessThan => actual < value
            LessOrEqual => actual <= value
            GreaterThan => actual > value
            GreaterOrEqual => actual >= value
          }
          if matched {
            ConditionTrue
          } else {
            ConditionFalse
          }
        }
        Some(_) => ConditionUnknown
      }
    AllOf(conditions) => {
      let mut unknown = false
      for condition in conditions {
        match evaluate_condition(condition, request) {
          ConditionFalse => return ConditionFalse
          ConditionUnknown => unknown = true
          ConditionTrue => ()
        }
      }
      if unknown {
        ConditionUnknown
      } else {
        ConditionTrue
      }
    }
    AnyOf(conditions) => {
      let mut unknown = false
      for condition in conditions {
        match evaluate_condition(condition, request) {
          ConditionTrue => return ConditionTrue
          ConditionUnknown => unknown = true
          ConditionFalse => ()
        }
      }
      if unknown {
        ConditionUnknown
      } else {
        ConditionFalse
      }
    }
    Not(condition) =>
      match evaluate_condition(condition, request) {
        ConditionTrue => ConditionFalse
        ConditionFalse => ConditionTrue
        ConditionUnknown => ConditionUnknown
      }
  }
}

///|
fn role_grants(
  policy : Policy,
  request : Request,
  trace : Array[String],
) -> Bool {
  let mut granted = false
  let visited : Map[String, Bool] = {}
  for binding in policy.bindings {
    if binding.subject == request.subject &&
      matcher_matches(binding.resource, request.resource) {
      if role_grants_recursive(
          policy,
          binding.role,
          request.action,
          visited,
          trace,
        ) {
        granted = true
      }
    }
  }
  granted
}

///|
fn role_grants_recursive(
  policy : Policy,
  role : String,
  action : String,
  visited : Map[String, Bool],
  trace : Array[String],
) -> Bool {
  if visited.contains(role) {
    return false
  }
  visited[role] = true
  let mut granted = false
  match policy.role_permissions.get(role) {
    Some(permissions) =>
      for permission in permissions {
        if permission == "*" || permission == action {
          trace.push("role:" + role + ":" + permission)
          granted = true
        }
      }
    None => ()
  }
  match policy.role_parents.get(role) {
    Some(parents) =>
      for parent in parents {
        if role_grants_recursive(policy, parent, action, visited, trace) {
          granted = true
        }
      }
    None => ()
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
