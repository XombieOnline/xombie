// Declaring our library as `no-std` unconditionally lets us be consistent
// in how we `use` items from `std` or `core`
#![no_std]

// We always pull in `std` during tests, because it's just easier
// to write tests when you can assume you're on a capable platform
#[cfg(any(feature = "std", test))]
#[allow(unused_imports)] // Justification: In case no macros are actually used
#[macro_use]
extern crate std;

// When we're building for a no-std target, we pull in `core`, but alias
// it as `std` so the `use` statements are the same between `std` and `core`.
#[cfg(all(not(feature = "std"), not(test)))]
#[allow(unused_imports)] // Justification: In case no macros are actually used
#[macro_use]
extern crate core as std;

pub mod account;
pub mod codec;
pub mod config_area;
pub mod config;
pub mod crypto;
pub mod eeprom;
pub mod fatx;
pub mod status;
