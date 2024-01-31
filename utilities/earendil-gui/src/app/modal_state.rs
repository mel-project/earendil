#[derive(Clone)]
pub struct ModalState(pub Severity, pub String);

#[derive(Clone, Copy)]
pub enum Severity {
    Info,
    Error,
}
