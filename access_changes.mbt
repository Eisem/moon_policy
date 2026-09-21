///|
/// An authorization result that changed between two policy versions.
pub(all) struct AccessChange {
  request : Request
  previous : Decision
  current : Decision
} derive(Debug, Eq)

///|
/// Whether the replacement policy grants or removes access for this request.
pub(all) enum AccessChangeKind {
  NewlyAllowed
  NewlyDenied
} derive(Debug, Eq)

///|
pub fn AccessChange::kind(self : AccessChange) -> AccessChangeKind {
  if self.current.allowed {
    NewlyAllowed
  } else {
    NewlyDenied
  }
}

///|
/// Evaluate the same request corpus against two policies and return only
/// changes in the access decision. Results retain the corpus order.
pub fn Policy::access_changes(
  self : Policy,
  replacement : Policy,
  requests : Array[Request],
) -> Array[AccessChange] {
  let changes : Array[AccessChange] = []
  for request in requests {
    let previous = self.authorize(request)
    let current = replacement.authorize(request)
    if previous.allowed != current.allowed {
      changes.push({ request, previous, current, })
    }
  }
  changes
}

///|
/// Serialize an access regression as a request plus the two decisions.
pub fn AccessChange::to_json(self : AccessChange) -> Json {
  Json::object({
    "kind": Json::string(
      match self.kind() {
        NewlyAllowed => "newly_allowed"
        NewlyDenied => "newly_denied"
      },
    ),
    "request": self.request.to_json(),
    "previous": self.previous.to_json(),
    "current": self.current.to_json(),
  })
}
