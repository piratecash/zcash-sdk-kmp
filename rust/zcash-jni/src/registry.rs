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

/// Changes an open wallet in place, under the registry lock. A closed handle is left closed.
pub fn update(handle: i64, change: impl FnOnce(&mut Coin)) {
    if let Some(slot) = handles().get_mut(&handle) {
        change(slot);
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
    fn update_open_wallet_changes_the_live_slot() {
        let handle = insert(coin("f.db"));

        update(handle, |coin| coin.url = "https://a.example".to_string());

        assert_eq!(get(handle).unwrap().url, "https://a.example");
    }

    #[test]
    fn update_account_landing_after_a_server_update_keeps_the_new_server() {
        let handle = insert(coin("g.db"));
        let account = get(handle).unwrap().account + 1;

        update(handle, |coin| coin.url = "https://b.example".to_string());
        update(handle, |coin| coin.account = account);

        let coin = get(handle).unwrap();
        assert_eq!(coin.url, "https://b.example");
        assert_eq!(coin.account, account);
    }

    #[test]
    fn update_closed_handle_does_nothing() {
        let handle = insert(coin("h.db"));
        remove(handle);

        update(handle, |coin| coin.url = "https://c.example".to_string());

        assert!(get(handle).is_none());
    }
}
