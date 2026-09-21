///|
/// A non-blocking warning about a policy that is valid but may be too broad,
/// redundant, or ineffective.
pub(all) struct PolicyWarning {
  code : String
  location : String
  message : String
} derive(Debug, Eq)

///|
fn policy_warning(
  code : String,
  location : String,
  message : String,
) -> PolicyWarning {
  { code, location, message, }
}

///|
fn rule_body_equal(left : Rule, right : Rule) -> Bool {
  left.effect == right.effect &&
  left.subject == right.subject &&
  left.action == right.action &&
  left.resource == right.resource &&
  left.condition == right.condition
}

///|
fn condition_never_satisfied(condition : Condition) -> Bool {
  match condition {
    Not(Always) | Not(Exists(_)) => true
    AllOf(children) => {
      for child in children {
        if condition_never_satisfied(child) {
          return true
        }
      }
      false
    }
    AnyOf(children) => {
      if children.length() == 0 {
        return true
      }
      for child in children {
        if !condition_never_satisfied(child) {
          return false
        }
      }
      true
    }
    _ => false
  }
}

///|
/// Find valid but suspicious policy constructs. Warnings do not block JSON
/// loading or authorization; `validate` remains the strict error check.
pub fn Policy::lint(self : Policy) -> Array[PolicyWarning] {
  let warnings : Array[PolicyWarning] = []
  for role, permissions in self.role_permissions {
    let seen : Map[String, Bool] = Map([])
    for index, permission in permissions {
      let location = "roles." + role + "." + index.to_string()
      if permission == "*" {
        warnings.push(
          policy_warning(
            "wildcard_permission", location, "role grants every action",
          ),
        )
      }
      if seen.contains(permission) {
        warnings.push(
          policy_warning("duplicate_permission", location, permission),
        )
      }
      seen[permission] = true
    }
  }
  for role, parents in self.role_parents {
    let seen : Map[String, Bool] = Map([])
    for index, parent in parents {
      let location = "role_parents." + role + "." + index.to_string()
      if seen.contains(parent) {
        warnings.push(policy_warning("duplicate_parent", location, parent))
      }
      seen[parent] = true
    }
  }
  for index, rule in self.rules {
    let location = "rules." + index.to_string()
    if rule.effect is Allow &&
      rule.subject is Any &&
      rule.action is Any &&
      rule.resource is Any &&
      rule.condition is Always {
      warnings.push(
        policy_warning(
          "unrestricted_allow", location, "rule grants every request",
        ),
      )
    }
    if rule.effect is Allow && condition_never_satisfied(rule.condition) {
      warnings.push(
        policy_warning(
          "ineffective_allow", location, "condition cannot become satisfied",
        ),
      )
    }
    for previous_index in 0..<index {
      if rule_body_equal(self.rules[previous_index], rule) {
        warnings.push(
          policy_warning(
            "duplicate_rule_body",
            location,
            "same effect, matchers, and condition as rules." +
            previous_index.to_string(),
          ),
        )
        break
      }
    }
  }
  warnings
}

///|
/// Serialize a warning for editor integrations and the command-line linter.
pub fn PolicyWarning::to_json(self : PolicyWarning) -> Json {
  Json::object({
    "code": Json::string(self.code),
    "location": Json::string(self.location),
    "message": Json::string(self.message),
  })
}
