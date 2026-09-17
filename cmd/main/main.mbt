///|
/// Entry point for the CLI or runnable program in this template.
/// Keep main focused; move logic into the library package.
/// Run with `moon run cmd/main` from the project root.
fn main {
  let policy = @policy.Policy(
    role_permissions={ "editor": ["document:read"] },
    bindings=[RoleBinding(subject="alice", role="editor")],
  )
  let decision = policy.authorize(
    Request(subject="alice", action="document:read", resource="document:demo"),
  )
  println("allowed: \{decision.allowed}")
  println("reason: \{to_repr(decision.reason)}")
}
