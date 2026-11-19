pub mod config;
mod nats;

pub use nats::run;
/// The wire format, shared with every other monitor on the bus.
pub use nats::{ParseError, WIRE_VERSION, WireAction, WireEvent};
