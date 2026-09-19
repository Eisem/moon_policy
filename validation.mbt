///|
/// A static problem with a policy before it is used to authorize requests.
pub(all) struct PolicyIssue {
  code : String
  location : String
  message : String
} derive(Debug, Eq)

///|
fn policy_issue(
  code : String,
  location : String,
  message : String,
) -> PolicyIssue {
  { code, location, message }
}

///|
fn valid_attribute_path(path : String) -> Bool {
  let parts = path.split(".").to_array()
  if parts.length() < 2 ||
    !(parts[0] == "subject" || parts[0] == "resource" || parts[0] == "context") {
    return false
  }
  for part in parts {
    if part == "" {
      return false
    }
  }
  true
}

///|
fn same_attribute_type(left : AttributeValue, right : AttributeValue) -> Bool {
  match (left, right) {
    (StringValue(_), StringValue(_))
    | (StringListValue(_), StringListValue(_))
    | (ObjectValue(_), ObjectValue(_))
    | (BoolValue(_), BoolValue(_))
    | (IntValue(_), IntValue(_)) => true
    _ => false
  }
}

///|
fn validate_condition(
  condition : Condition,
  location : String,
  issues : Array[PolicyIssue],
) -> Unit {
  match condition {
    Always => ()
    Exists(path) =>
      if !valid_attribute_path(path) {
        issues.push(policy_issue("invalid_attribute_path", location, path))
      }
    Equals(path~, ..)
    | Compare(path~, ..)
    | Contains(path~, ..)
    | StringMatches(path~, ..) =>
      if !valid_attribute_path(path) {
        issues.push(policy_issue("invalid_attribute_path", location, path))
      }
    ContainsAny(path~, values~) | ContainsAll(path~, values~) => {
      if !valid_attribute_path(path) {
        issues.push(policy_issue("invalid_attribute_path", location, path))
      }
      if values.length() == 0 {
        issues.push(
          policy_issue("empty_string_set", location, "string set is empty"),
        )
      }
    }
    OneOf(path~, values~) => {
      if !valid_attribute_path(path) {
        issues.push(policy_issue("invalid_attribute_path", location, path))
      }
      if values.length() == 0 {
        issues.push(
          policy_issue("empty_value_set", location, "value set is empty"),
        )
      } else {
        for value in values {
          if !same_attribute_type(values[0], value) {
            issues.push(
              policy_issue(
                "mixed_value_types", location, "value set has mixed types",
              ),
            )
            break
          }
        }
      }
    }
    Same(left~, right~) => {
      if !valid_attribute_path(left) {
        issues.push(
          policy_issue("invalid_attribute_path", location + ".left", left),
        )
      }
      if !valid_attribute_path(right) {
        issues.push(
          policy_issue("invalid_attribute_path", location + ".right", right),
        )
      }
    }
    AllOf(conditions) | AnyOf(conditions) => {
      if conditions.length() == 0 {
        issues.push(
          policy_issue(
            "empty_condition_group", location, "condition group is empty",
          ),
        )
      }
      for index, child in conditions {
        validate_condition(child, location + "." + index.to_string(), issues)
      }
    }
    Not(child) => validate_condition(child, location + ".not", issues)
  }
}

///|
fn role_has_cycle(
  policy : Policy,
  role : String,
  states : Map[String, Int],
) -> Bool {
  match states.get(role) {
    Some(1) => return true
    Some(2) => return false
    _ => ()
  }
  states[role] = 1
  match policy.role_parents.get(role) {
    Some(parents) =>
      for parent in parents {
        if role_has_cycle(policy, parent, states) {
          return true
        }
      }
    None => ()
  }
  states[role] = 2
  false
}

///|
/// Check a policy for ambiguous or broken configuration before evaluating it.
/// The returned issues are ordered by role, binding, and then rule order.
pub fn Policy::validate(self : Policy) -> Array[PolicyIssue] {
  let issues : Array[PolicyIssue] = []
  for role, permissions in self.role_permissions {
    if role == "" {
      issues.push(policy_issue("empty_role", "roles", "role name is empty"))
    }
    for index, permission in permissions {
      if permission == "" {
        issues.push(
          policy_issue(
            "empty_permission",
            "roles." + role + "." + index.to_string(),
            "permission is empty",
          ),
        )
      }
    }
  }
  for role, parents in self.role_parents {
    if !self.role_permissions.contains(role) {
      issues.push(policy_issue("unknown_role", "role_parents." + role, role))
    }
    for index, parent in parents {
      if !self.role_permissions.contains(parent) {
        issues.push(
          policy_issue(
            "unknown_parent_role",
            "role_parents." + role + "." + index.to_string(),
            parent,
          ),
        )
      }
    }
  }
  let role_states : Map[String, Int] = {}
  for role, _ in self.role_permissions {
    if role_has_cycle(self, role, role_states) {
      issues.push(policy_issue("role_inheritance_cycle", "role_parents", role))
      break
    }
  }
  let bindings_seen : Array[RoleBinding] = []
  for index, binding in self.bindings {
    let location = "bindings." + index.to_string()
    if binding.subject == "" {
      issues.push(policy_issue("empty_subject", location, "subject is empty"))
    }
    if !self.role_permissions.contains(binding.role) {
      issues.push(policy_issue("unknown_role", location, binding.role))
    }
    for previous in bindings_seen {
      if previous == binding {
        issues.push(
          policy_issue(
            "duplicate_binding",
            location,
            binding.subject + ":" + binding.role,
          ),
        )
        break
      }
    }
    bindings_seen.push(binding)
  }
  let rule_ids_seen : Map[String, Bool] = {}
  for index, rule in self.rules {
    let location = "rules." + index.to_string()
    if rule.id == "" {
      issues.push(policy_issue("empty_rule_id", location, "rule id is empty"))
    } else if rule_ids_seen.contains(rule.id) {
      issues.push(policy_issue("duplicate_rule_id", location, rule.id))
    }
    rule_ids_seen[rule.id] = true
    validate_condition(rule.condition, location + ".condition", issues)
  }
  issues
}
