#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_protocol::repository_name(), "alani-protocol");
    assert!(!alani_protocol::module_names().is_empty());
}
