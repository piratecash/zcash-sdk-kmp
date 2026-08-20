//! Open wallets, keyed by an opaque handle.
//!
//! A `Coin` is cloned out under a short lock, so a long call never holds the registry.

use rlz::api::coin::Coin;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

static HANDLES: LazyLock<Mutex<HashMap<i64, Coin>>> = LazyLock::new(Default::default);

/// Starts at 1: 0 is never a valid handle, so a zeroed Kotlin field cannot address a wallet.
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

fn handles() -> MutexGuard<'static, HashMap<i64, Coin>> {
    HANDLES.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn insert(coin: Coin) -> i64 {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    handles().insert(handle, coin);
    handle
}

pub fn get(handle: i64) -> Option<Coin> {
    handles().get(&handle).cloned()
}

/// Replaces an open wallet's state. A handle closed meanwhile is not resurrected.
pub fn replace(handle: i64, coin: Coin) {
    if let Some(slot) = handles().get_mut(&handle) {
        *slot = coin;
    }
}

pub fn remove(handle: i64) {
    handles().remove(&handle);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(path: &str) -> Coin {
        Coin {
            db_filepath: path.to_string(),
            ..Coin::new(Some(0))
        }
    }

    #[test]
    fn insert_then_get_returns_the_same_wallet() {
        let handle = insert(coin("a.db"));
        assert_eq!(get(handle).unwrap().db_filepath, "a.db");
    }

    #[test]
    fn handles_are_never_zero_and_never_repeat() {
        let first = insert(coin("b.db"));
        let second = insert(coin("c.db"));
        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second);
    }

    #[test]
    fn remove_is_idempotent_and_makes_the_handle_unknown() {
        let handle = insert(coin("d.db"));
        remove(handle);
        remove(handle);
        assert!(get(handle).is_none());
    }

    #[test]
    fn get_unknown_handle_returns_none() {
        assert!(get(-1).is_none());
        assert!(get(0).is_none());
    }

    #[test]
    fn replace_updates_an_open_wallet_and_ignores_a_closed_one() {
        let handle = insert(coin("e.db"));
        replace(handle, coin("e2.db"));
        assert_eq!(get(handle).unwrap().db_filepath, "e2.db");

        remove(handle);
        replace(handle, coin("e3.db"));
        assert!(get(handle).is_none());
    }
}
