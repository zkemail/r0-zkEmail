mod structs;
pub use structs::*;

#[cfg(feature = "host")]
mod input_generator;
#[cfg(feature = "host")]
pub use input_generator::*;
