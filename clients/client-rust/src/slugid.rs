use uuid;

/// Returns a randomly generated uuid v4 compliant slug
pub fn v4() -> String {
    uuid::Uuid::new_v4().to_simple().to_string()[..22].to_string()
}

/// In the rust implementation, the same as v4()
pub fn nice() -> String {
    v4()
}
