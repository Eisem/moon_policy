///|
/// One request paired with its authorization decision in a batch result.
pub(all) struct AuthorizationResult {
  request : Request
  decision : Decision
} derive(Debug, Eq)

///|
/// Authorize a request collection while retaining its input order. Requests
/// are evaluated independently with the same semantics as `authorize`.
pub fn Policy::authorize_batch(
  self : Policy,
  requests : Array[Request],
) -> Array[AuthorizationResult] {
  [
    for request in requests => { request, decision: self.authorize(request) }
  ]
}

///|
/// Serialize a batch item as its original request and resulting decision.
pub fn AuthorizationResult::to_json(self : AuthorizationResult) -> Json {
  Json::object({
    "request": self.request.to_json(),
    "decision": self.decision.to_json(),
  })
}

///|
/// Serialize a batch result array for transport or audit storage.
pub fn authorization_results_to_json(
  results : Array[AuthorizationResult],
) -> Json {
  Json::array([ for result in results => result.to_json() ])
}
