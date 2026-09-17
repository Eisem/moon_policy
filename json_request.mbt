///|
fn decode_attribute_map(
  value : Json,
  field~ : String,
) -> Map[String, AttributeValue] raise PolicyParseError {
  let object = expect_object(value, field~)
  let attributes : Map[String, AttributeValue] = {}
  for name, item in object {
    if name == "" {
      raise InvalidPolicy(field + " contains an empty attribute name")
    }
    attributes[name] = decode_attribute_value(item, field=field + "." + name)
  }
  attributes
}

///|
fn decode_optional_attributes(
  object : Map[String, Json],
  field : String,
) -> Map[String, AttributeValue] raise PolicyParseError {
  match object.get(field) {
    Some(value) => decode_attribute_map(value, field~)
    None => {}
  }
}

///|
/// Decode a JSON authorization request. The required keys are `subject`,
/// `action`, and `resource`. The optional `subject_attributes`,
/// `resource_attributes`, and `context` maps contain scalar values.
pub fn request_from_json(source : String) -> Request raise PolicyParseError {
  let root = @json.parse(source) catch {
    error => raise InvalidJson(error.to_string())
  }
  let object = expect_object(root, field="request")
  let subject = expect_string(
    required_field(object, "subject"),
    field="subject",
  )
  let action = expect_string(required_field(object, "action"), field="action")
  let resource = expect_string(
    required_field(object, "resource"),
    field="resource",
  )
  if subject == "" || action == "" || resource == "" {
    raise InvalidPolicy("subject, action, and resource must not be empty")
  }
  Request(
    subject~,
    action~,
    resource~,
    subject_attributes=decode_optional_attributes(object, "subject_attributes"),
    resource_attributes=decode_optional_attributes(
      object, "resource_attributes",
    ),
    context=decode_optional_attributes(object, "context"),
  )
}

///|
fn DecisionReason::as_string(self : DecisionReason) -> String {
  match self {
    Allowed => "allowed"
    ExplicitDeny => "explicit_deny"
    NoMatchingRule => "no_matching_rule"
  }
}

///|
/// Serialize a decision as stable, machine-readable JSON.
pub fn Decision::to_json(self : Decision) -> Json {
  Json::object({
    "allowed": Json::boolean(self.allowed),
    "reason": Json::string(self.reason.as_string()),
    "trace": Json::array([ for item in self.trace => Json::string(item) ]),
  })
}
