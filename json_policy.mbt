///|
/// Errors raised while decoding a JSON policy document.
pub(all) suberror PolicyParseError {
  InvalidJson(String)
  MissingField(String)
  ExpectedType(field~ : String, expected~ : String)
  InvalidEffect(String)
  InvalidCondition(String)
  InvalidPolicy(String)
  UnknownField(String)
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
fn reject_unknown_fields(
  object : Map[String, Json],
  allowed : Array[String],
  location : String,
) -> Unit raise PolicyParseError {
  for field, _ in object {
    let mut known = false
    for candidate in allowed {
      if field == candidate {
        known = true
        break
      }
    }
    if !known {
      raise UnknownField(location + "." + field)
    }
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
    reject_unknown_fields(object, ["subject", "role", "resource"], "bindings[]")
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
        resource=decode_optional_matcher(object, "resource", "bindings[]"),
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
  decode_attribute_value_at_depth(value, field, 0)
}

///|
fn decode_attribute_value_at_depth(
  value : Json,
  field : String,
  depth : Int,
) -> AttributeValue raise PolicyParseError {
  if depth > 16 {
    raise InvalidPolicy("attribute nesting exceeds 16 levels at " + field)
  }
  match value {
    String(string) => StringValue(string)
    Object(fields) => {
      let values : Map[String, AttributeValue] = {}
      for name, item in fields {
        if name == "" {
          raise InvalidPolicy(field + " contains an empty attribute name")
        }
        values[name] = decode_attribute_value_at_depth(
          item,
          field + "." + name,
          depth + 1,
        )
      }
      ObjectValue(values)
    }
    Array(items) => {
      let values : Array[String] = []
      for item in items {
        values.push(expect_string(item, field=field + "[]"))
      }
      StringListValue(values)
    }
    True => BoolValue(true)
    False => BoolValue(false)
    Number(number, ..) => {
      let integer = number.to_int()
      if Double::from_int(integer) == number {
        IntValue(integer)
      } else {
        raise ExpectedType(
          field~,
          expected="string, string array, object, boolean, or integer",
        )
      }
    }
    _ =>
      raise ExpectedType(
        field~,
        expected="string, string array, object, boolean, or integer",
      )
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
fn decode_same(value : Json) -> Condition raise PolicyParseError {
  let object = expect_object(value, field="rules[].condition.same")
  if object.length() != 2 {
    raise InvalidCondition("same requires only left and right")
  }
  Same(
    left=expect_string(
      required_field(object, "left"),
      field="rules[].condition.same.left",
    ),
    right=expect_string(
      required_field(object, "right"),
      field="rules[].condition.same.right",
    ),
  )
}

///|
fn decode_one_of(value : Json) -> Condition raise PolicyParseError {
  let object = expect_object(value, field="rules[].condition.one_of")
  if object.length() != 2 {
    raise InvalidCondition("one_of requires only path and values")
  }
  let source = expect_array(
    required_field(object, "values"),
    field="rules[].condition.one_of.values",
  )
  let values : Array[AttributeValue] = []
  for item in source {
    values.push(
      decode_attribute_value(item, field="rules[].condition.one_of.values[]"),
    )
  }
  OneOf(
    path=expect_string(
      required_field(object, "path"),
      field="rules[].condition.one_of.path",
    ),
    values~,
  )
}

///|
fn decode_contains(value : Json) -> Condition raise PolicyParseError {
  let object = expect_object(value, field="rules[].condition.contains")
  if object.length() != 2 {
    raise InvalidCondition("contains requires only path and value")
  }
  Contains(
    path=expect_string(
      required_field(object, "path"),
      field="rules[].condition.contains.path",
    ),
    value=expect_string(
      required_field(object, "value"),
      field="rules[].condition.contains.value",
    ),
  )
}

///|
fn decode_string_values(
  value : Json,
  field : String,
) -> Array[String] raise PolicyParseError {
  let source = expect_array(value, field~)
  let values : Array[String] = []
  for item in source {
    values.push(expect_string(item, field=field + "[]"))
  }
  values
}

///|
fn decode_matcher_value(
  value : Json,
  field : String,
) -> Matcher raise PolicyParseError {
  match value {
    String(exact) => Exact(exact)
    Object(spec) => {
      if spec.length() != 1 {
        raise ExpectedType(field~, expected="string or one-key glob object")
      }
      match spec.get("glob") {
        Some(pattern) => Glob(expect_string(pattern, field=field + ".glob"))
        None =>
          raise ExpectedType(field~, expected="string or one-key glob object")
      }
    }
    _ => raise ExpectedType(field~, expected="string or one-key glob object")
  }
}

///|
fn decode_string_match(value : Json) -> Condition raise PolicyParseError {
  let object = expect_object(value, field="rules[].condition.string_matches")
  if object.length() != 2 {
    raise InvalidCondition("string_matches requires only path and matcher")
  }
  StringMatches(
    path=expect_string(
      required_field(object, "path"),
      field="rules[].condition.string_matches.path",
    ),
    matcher=decode_matcher_value(
      required_field(object, "matcher"),
      "rules[].condition.string_matches.matcher",
    ),
  )
}

///|
fn decode_list_membership(
  value : Json,
  operator : String,
) -> Condition raise PolicyParseError {
  let field = "rules[].condition." + operator
  let object = expect_object(value, field~)
  if object.length() != 2 {
    raise InvalidCondition(operator + " requires only path and values")
  }
  let path = expect_string(
    required_field(object, "path"),
    field=field + ".path",
  )
  let values = decode_string_values(
    required_field(object, "values"),
    field + ".values",
  )
  if operator == "contains_any" {
    ContainsAny(path~, values~)
  } else {
    ContainsAll(path~, values~)
  }
}

///|
fn decode_condition(value : Json) -> Condition raise PolicyParseError {
  let object = expect_object(value, field="rules[].condition")
  if object.length() != 1 {
    raise InvalidCondition("a condition must have exactly one operator")
  }
  match object.get("exists") {
    Some(path) =>
      return Exists(expect_string(path, field="rules[].condition.exists"))
    None => ()
  }
  match object.get("equals") {
    Some(equals) => {
      let fields = expect_object(equals, field="rules[].condition.equals")
      if fields.length() != 2 {
        raise InvalidCondition("equals requires only path and value")
      }
      return Equals(
        path=expect_string(
          required_field(fields, "path"),
          field="rules[].condition.equals.path",
        ),
        value=decode_attribute_value(
          required_field(fields, "value"),
          field="rules[].condition.equals.value",
        ),
      )
    }
    None => ()
  }
  match object.get("same") {
    Some(same) => return decode_same(same)
    None => ()
  }
  match object.get("one_of") {
    Some(one_of) => return decode_one_of(one_of)
    None => ()
  }
  match object.get("contains") {
    Some(contains) => return decode_contains(contains)
    None => ()
  }
  match object.get("string_matches") {
    Some(spec) => return decode_string_match(spec)
    None => ()
  }
  match object.get("contains_any") {
    Some(spec) => return decode_list_membership(spec, "contains_any")
    None => ()
  }
  match object.get("contains_all") {
    Some(spec) => return decode_list_membership(spec, "contains_all")
    None => ()
  }
  match object.get("compare") {
    Some(compare) => return decode_compare(compare)
    None => ()
  }
  match object.get("all") {
    Some(conditions) =>
      return AllOf(decode_conditions(conditions, field="rules[].condition.all"))
    None => ()
  }
  match object.get("any") {
    Some(conditions) =>
      return AnyOf(decode_conditions(conditions, field="rules[].condition.any"))
    None => ()
  }
  match object.get("not") {
    Some(condition) => return Not(decode_condition(condition))
    None => ()
  }
  raise InvalidCondition(
    "expected exists, equals, same, one_of, contains, string_matches, contains_any, contains_all, compare, all, any, or not",
  )
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
  location : String,
) -> Matcher raise PolicyParseError {
  match object.get(field) {
    None => Any
    Some(value) => decode_matcher_value(value, location + "." + field)
  }
}

///|
fn decode_rules(value : Json) -> Array[Rule] raise PolicyParseError {
  let entries = expect_array(value, field="rules")
  let rules : Array[Rule] = []
  for entry in entries {
    let object = expect_object(entry, field="rules[]")
    reject_unknown_fields(
      object,
      ["id", "effect", "subject", "action", "resource", "condition"],
      "rules[]",
    )
    rules.push(
      Rule(
        id=expect_string(required_field(object, "id"), field="rules[].id"),
        effect=decode_effect(required_field(object, "effect")),
        subject=decode_optional_matcher(object, "subject", "rules[]"),
        action=decode_optional_matcher(object, "action", "rules[]"),
        resource=decode_optional_matcher(object, "resource", "rules[]"),
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
/// `roles`, `role_parents`, `bindings`, and `rules` are optional. Unknown fields
/// are rejected to prevent misspelled restrictions from widening access.
pub fn policy_from_json(source : String) -> Policy raise PolicyParseError {
  let root = @json.parse(source) catch {
    error => raise InvalidJson(error.to_string())
  }
  let object = expect_object(root, field="policy")
  reject_unknown_fields(
    object,
    ["roles", "role_parents", "bindings", "rules"],
    "policy",
  )
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
