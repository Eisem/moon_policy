///|
fn attribute_value_to_json(value : AttributeValue) -> Json {
  match value {
    StringValue(text) => Json::string(text)
    StringListValue(values) =>
      Json::array([ for value in values => Json::string(value) ])
    ObjectValue(fields) => {
      let object : Map[String, Json] = {}
      for name, item in fields {
        object[name] = attribute_value_to_json(item)
      }
      Json::object(object)
    }
    BoolValue(flag) => Json::boolean(flag)
    IntValue(number) => Json::number(Double::from_int(number))
  }
}

///|
fn matcher_to_json(matcher : Matcher) -> Json {
  match matcher {
    Exact(value) => Json::string(value)
    Glob(pattern) => Json::object({ "glob": Json::string(pattern) })
    Any => Json::string("")
  }
}

///|
fn comparison_to_string(op : Comparison) -> String {
  match op {
    LessThan => "lt"
    LessOrEqual => "lte"
    GreaterThan => "gt"
    GreaterOrEqual => "gte"
  }
}

///|
fn condition_to_json(condition : Condition) -> Json {
  match condition {
    Always => Json::object({})
    Exists(path) => Json::object({ "exists": Json::string(path) })
    Equals(path~, value~) =>
      Json::object({
        "equals": Json::object({
          "path": Json::string(path),
          "value": attribute_value_to_json(value),
        }),
      })
    Same(left~, right~) =>
      Json::object({
        "same": Json::object({
          "left": Json::string(left),
          "right": Json::string(right),
        }),
      })
    OneOf(path~, values~) =>
      Json::object({
        "one_of": Json::object({
          "path": Json::string(path),
          "values": Json::array(
            [
              for value in values => attribute_value_to_json(value)
            ],
          ),
        }),
      })
    Contains(path~, value~) =>
      Json::object({
        "contains": Json::object({
          "path": Json::string(path),
          "value": Json::string(value),
        }),
      })
    StringMatches(path~, matcher~) =>
      Json::object({
        "string_matches": Json::object({
          "path": Json::string(path),
          "matcher": matcher_to_json(matcher),
        }),
      })
    ContainsAny(path~, values~) =>
      Json::object({
        "contains_any": Json::object({
          "path": Json::string(path),
          "values": Json::array([ for value in values => Json::string(value) ]),
        }),
      })
    ContainsAll(path~, values~) =>
      Json::object({
        "contains_all": Json::object({
          "path": Json::string(path),
          "values": Json::array([ for value in values => Json::string(value) ]),
        }),
      })
    Compare(path~, op~, value~) =>
      Json::object({
        "compare": Json::object({
          "path": Json::string(path),
          "op": Json::string(comparison_to_string(op)),
          "value": Json::number(Double::from_int(value)),
        }),
      })
    AllOf(conditions) =>
      Json::object({
        "all": Json::array(
          [
            for child in conditions => condition_to_json(child)
          ],
        ),
      })
    AnyOf(conditions) =>
      Json::object({
        "any": Json::array(
          [
            for child in conditions => condition_to_json(child)
          ],
        ),
      })
    Not(child) => Json::object({ "not": condition_to_json(child) })
  }
}

///|
fn Rule::to_json(self : Rule) -> Json {
  let object : Map[String, Json] = {
    "id": Json::string(self.id),
    "effect": Json::string(
      match self.effect {
        Allow => "allow"
        Deny => "deny"
      },
    ),
  }
  if !(self.subject is Any) {
    object["subject"] = matcher_to_json(self.subject)
  }
  if !(self.action is Any) {
    object["action"] = matcher_to_json(self.action)
  }
  if !(self.resource is Any) {
    object["resource"] = matcher_to_json(self.resource)
  }
  if !(self.condition is Always) {
    object["condition"] = condition_to_json(self.condition)
  }
  Json::object(object)
}

///|
fn RoleBinding::to_json(self : RoleBinding) -> Json {
  let object : Map[String, Json] = {
    "subject": Json::string(self.subject),
    "role": Json::string(self.role),
  }
  if !(self.resource is Any) {
    object["resource"] = matcher_to_json(self.resource)
  }
  Json::object(object)
}

///|
/// Serialize a policy to the documented JSON representation. A valid policy
/// can be loaded again with `policy_from_json` without changing its behavior.
pub fn Policy::to_json(self : Policy) -> Json {
  let roles : Map[String, Json] = {}
  for role, permissions in self.role_permissions {
    roles[role] = Json::array(
      [
        for permission in permissions => Json::string(permission)
      ],
    )
  }
  let parents : Map[String, Json] = {}
  for role, inherited in self.role_parents {
    parents[role] = Json::array(
      [
        for parent in inherited => Json::string(parent)
      ],
    )
  }
  Json::object({
    "roles": Json::object(roles),
    "role_parents": Json::object(parents),
    "bindings": Json::array(
      [
        for binding in self.bindings => binding.to_json()
      ],
    ),
    "rules": Json::array([ for rule in self.rules => rule.to_json() ]),
  })
}
