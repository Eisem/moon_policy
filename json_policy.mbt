///|
/// Errors raised while decoding a JSON policy document.
pub(all) suberror PolicyParseError {
  InvalidJson(String)
  MissingField(String)
  ExpectedType(field~ : String, expected~ : String)
  InvalidEffect(String)
  InvalidCondition(String)
  InvalidPolicy(String)
} derive(Debug, Eq)

///|
fn expect_object(
  value : Json,
  field~ : String,
) -> Map[String, Json] raise PolicyParseError {
  match value {
    Object(object) => object
    _ => raise ExpectedType(field~, expected="object")
  }
}

///|
fn expect_array(
  value : Json,
  field~ : String,
) -> Array[Json] raise PolicyParseError {
  match value {
    Array(array) => array
    _ => raise ExpectedType(field~, expected="array")
  }
}

///|
fn expect_string(
  value : Json,
  field~ : String,
) -> String raise PolicyParseError {
  match value {
    String(string) => string
    _ => raise ExpectedType(field~, expected="string")
  }
}

///|
fn required_field(
  object : Map[String, Json],
  field : String,
) -> Json raise PolicyParseError {
  match object.get(field) {
    Some(value) => value
    None => raise MissingField(field)
  }
}

///|
fn decode_permissions(
  value : Json,
  field~ : String,
) -> Array[String] raise PolicyParseError {
  let permissions = expect_array(value, field~)
  let decoded : Array[String] = []
  for permission in permissions {
    decoded.push(expect_string(permission, field~))
  }
  decoded
}

///|
fn decode_roles(
  value : Json,
  field~ : String,
) -> Map[String, Array[String]] raise PolicyParseError {
  let object = expect_object(value, field~)
  let roles : Map[String, Array[String]] = {}
  for role, permissions in object {
    roles[role] = decode_permissions(permissions, field=field + "." + role)
  }
  roles
}

///|
fn decode_bindings(value : Json) -> Array[RoleBinding] raise PolicyParseError {
  let entries = expect_array(value, field="bindings")
  let bindings : Array[RoleBinding] = []
  for entry in entries {
    let object = expect_object(entry, field="bindings[]")
    bindings.push(
      RoleBinding(
        subject=expect_string(
          required_field(object, "subject"),
          field="bindings[].subject",
        ),
        role=expect_string(
          required_field(object, "role"),
          field="bindings[].role",
        ),
      ),
    )
  }
  bindings
}

///|
fn decode_effect(value : Json) -> Effect raise PolicyParseError {
  match expect_string(value, field="rules[].effect") {
    "allow" => Allow
    "deny" => Deny
    other => raise InvalidEffect(other)
  }
}

///|
fn decode_attribute_value(
  value : Json,
  field~ : String,
) -> AttributeValue raise PolicyParseError {
  match value {
    String(string) => StringValue(string)
    True => BoolValue(true)
    False => BoolValue(false)
    Number(number, ..) => {
      let integer = number.to_int()
      if Double::from_int(integer) == number {
        IntValue(integer)
      } else {
        raise ExpectedType(field~, expected="string, boolean, or integer")
      }
    }
    _ => raise ExpectedType(field~, expected="string, boolean, or integer")
  }
}

///|
fn decode_comparison(value : Json) -> Comparison raise PolicyParseError {
  match expect_string(value, field="rules[].condition.compare.op") {
    "lt" => LessThan
    "lte" => LessOrEqual
    "gt" => GreaterThan
    "gte" => GreaterOrEqual
    _ => raise InvalidCondition("compare op must be lt, lte, gt, or gte")
  }
}

///|
fn decode_compare(value : Json) -> Condition raise PolicyParseError {
  let object = expect_object(value, field="rules[].condition.compare")
  if object.length() != 3 {
    raise InvalidCondition("compare requires only path, op, and value")
  }
  let threshold = decode_attribute_value(
    required_field(object, "value"),
    field="rules[].condition.compare.value",
  )
  match threshold {
    IntValue(value) =>
      Compare(
        path=expect_string(
          required_field(object, "path"),
          field="rules[].condition.compare.path",
        ),
        op=decode_comparison(required_field(object, "op")),
        value~,
      )
    _ =>
      raise ExpectedType(
        field="rules[].condition.compare.value",
        expected="integer",
      )
  }
}

///|
fn decode_condition(value : Json) -> Condition raise PolicyParseError {
  let object = expect_object(value, field="rules[].condition")
  if object.length() != 1 {
    raise InvalidCondition("a condition must have exactly one operator")
  }
  match object.get("exists") {
    Some(path) => Exists(expect_string(path, field="rules[].condition.exists"))
    None =>
      match object.get("equals") {
        Some(equals) => {
          let equals_object = expect_object(
            equals,
            field="rules[].condition.equals",
          )
          if equals_object.length() != 2 {
            raise InvalidCondition("equals requires only path and value")
          }
          Equals(
            path=expect_string(
              required_field(equals_object, "path"),
              field="rules[].condition.equals.path",
            ),
            value=decode_attribute_value(
              required_field(equals_object, "value"),
              field="rules[].condition.equals.value",
            ),
          )
        }
        None =>
          match object.get("compare") {
            Some(compare) => decode_compare(compare)
            None =>
              match object.get("all") {
                Some(conditions) =>
                  AllOf(
                    decode_conditions(conditions, field="rules[].condition.all"),
                  )
                None =>
                  match object.get("any") {
                    Some(conditions) =>
                      AnyOf(
                        decode_conditions(
                          conditions,
                          field="rules[].condition.any",
                        ),
                      )
                    None =>
                      match object.get("not") {
                        Some(condition) => Not(decode_condition(condition))
                        None =>
                          raise InvalidCondition(
                            "expected exists, equals, compare, all, any, or not",
                          )
                      }
                  }
              }
          }
      }
  }
}

///|
fn decode_conditions(
  value : Json,
  field~ : String,
) -> Array[Condition] raise PolicyParseError {
  let values = expect_array(value, field~)
  let conditions : Array[Condition] = []
  for value in values {
    conditions.push(decode_condition(value))
  }
  conditions
}

///|
fn decode_optional_matcher(
  object : Map[String, Json],
  field : String,
) -> Matcher raise PolicyParseError {
  match object.get(field) {
    None => Any
    Some(value) =>
      match value {
        String(exact) => Exact(exact)
        Object(spec) => {
          if spec.length() != 1 {
            raise ExpectedType(
              field="rules[]." + field,
              expected="string or one-key glob object",
            )
          }
          match spec.get("glob") {
            Some(pattern) =>
              Glob(expect_string(pattern, field="rules[]." + field + ".glob"))
            None =>
              raise ExpectedType(
                field="rules[]." + field,
                expected="string or one-key glob object",
              )
          }
        }
        _ =>
          raise ExpectedType(
            field="rules[]." + field,
            expected="string or one-key glob object",
          )
      }
  }
}

///|
fn decode_rules(value : Json) -> Array[Rule] raise PolicyParseError {
  let entries = expect_array(value, field="rules")
  let rules : Array[Rule] = []
  for entry in entries {
    let object = expect_object(entry, field="rules[]")
    rules.push(
      Rule(
        id=expect_string(required_field(object, "id"), field="rules[].id"),
        effect=decode_effect(required_field(object, "effect")),
        subject=decode_optional_matcher(object, "subject"),
        action=decode_optional_matcher(object, "action"),
        resource=decode_optional_matcher(object, "resource"),
        condition=match object.get("condition") {
          Some(condition) => decode_condition(condition)
          None => Always
        },
      ),
    )
  }
  rules
}

///|
/// Decode the documented JSON representation of a policy.
///
/// `roles`, `bindings`, and `rules` are optional. Unknown fields are ignored so
/// future policy metadata does not change the authorization semantics.
pub fn policy_from_json(source : String) -> Policy raise PolicyParseError {
  let root = @json.parse(source) catch {
    error => raise InvalidJson(error.to_string())
  }
  let object = expect_object(root, field="policy")
  let role_permissions = match object.get("roles") {
    Some(value) => decode_roles(value, field="roles")
    None => {}
  }
  let role_parents = match object.get("role_parents") {
    Some(value) => decode_roles(value, field="role_parents")
    None => {}
  }
  let bindings = match object.get("bindings") {
    Some(value) => decode_bindings(value)
    None => []
  }
  let rules = match object.get("rules") {
    Some(value) => decode_rules(value)
    None => []
  }
  let policy = Policy(role_permissions~, role_parents~, bindings~, rules~)
  let issues = policy.validate()
  if issues.length() > 0 {
    raise InvalidPolicy(issues[0].code + " at " + issues[0].location)
  }
  policy
}
