//Declares the defines privately
mod defines;

pub mod execution;
pub mod io;
pub mod util;

// Re-exports the defines globally in the base namespace of the crate (i love buzzwords im
// buzzwording all over the floor)
pub use defines::*;
