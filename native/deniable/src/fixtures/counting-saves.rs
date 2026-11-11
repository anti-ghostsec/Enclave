//! Writes `counting-saves.bin`: a container as the crate made them before the
//! save marker cycled, when each superblock counted its saves.
//!
//! The crate can no longer write one, so this runs against the last version
//! that did. From a checkout of this repository:
//!
//! ```sh
//! git worktree add /tmp/counting 85c1dbd
//! mkdir /tmp/counting/native/deniable/examples
//! cp native/deniable/src/fixtures/counting-saves.rs /tmp/counting/native/deniable/examples/
//! (cd /tmp/counting/native && cargo run --release -p deniable --example counting-saves -- out.bin)
//! ```
//!
//! Salts, nonces and block positions are random, so no two runs give the same
//! bytes. What the test relies on is fixed: the two keys, what each volume
//! holds, and that one was saved six times and the other three.

use deniable::{Kdf, MemDevice, Store};

fn main() {
    let out = std::env::args().nth(1).expect("the file to write");
    // The cost the crate's tests use.
    let fast = Kdf { memory_kib: 64, passes: 1, lanes: 1 };
    let mut store = Store::format(MemDevice::new(96), fast).unwrap();

    let a = store.create_key(&[7u8; 32], &[]).unwrap();
    for n in 1..=3 {
        store.write(a, 0, &vec![n as u8; 9000]).unwrap();
        store.flush().unwrap();
    }
    let b = store.create_key(&[9u8; 32], &[a]).unwrap();
    store.write(b, 0, &[101u8; 5000]).unwrap();
    store.write(a, 0, &[4u8; 9000]).unwrap();
    store.flush().unwrap();
    store.write(a, 0, &[4u8; 9000]).unwrap();
    store.flush().unwrap();

    std::fs::write(out, store.into_device().into_bytes()).unwrap();
}
