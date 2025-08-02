// This file orchestrates the container module.
// It declares submodules and re-exports public items.

pub mod core;
pub mod specialized;
pub mod utils;

pub use self::core::Container;
pub use self::core::Borrow;

#[cfg(test)]
mod tests;
