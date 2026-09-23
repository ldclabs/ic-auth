//! A small cache of BLS signatures that have already been verified.
//!
//! Every canister signature carries a subnet delegation certificate, and that
//! certificate is stable for long stretches: the same public key, signature and
//! message are re-verified on request after request. A BLS verification is by
//! far the most expensive step of [`verify_certificate`](crate::verify_certificate),
//! and inside a canister it is paid for in cycles, so remembering the
//! successful ones is worth a few kilobytes.
//!
//! Entries are keyed by a SHA-256 digest of the verification inputs rather than
//! the inputs themselves, which keeps each entry small and fixed-size.
//! Eviction is first-in-first-out: an LRU would serve marginally better, but
//! the working set here is a handful of subnet keys, not a long tail.

use sha2::{Digest, Sha256};
use std::{
    collections::{HashSet, VecDeque},
    sync::{LazyLock, Mutex},
};

/// A verified `(public_key, signature, message)` triple.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignatureCacheEntry([u8; 32]);

/// The process-wide cache.
///
/// It only ever holds digests of signatures that verified, so a poisoned lock
/// carries no unsound state and is recovered rather than propagated.
pub struct SignatureCache {
    inner: Mutex<Inner>,
    capacity: usize,
}

struct Inner {
    entries: HashSet<SignatureCacheEntry>,
    order: VecDeque<SignatureCacheEntry>,
}

static GLOBAL: LazyLock<SignatureCache> = LazyLock::new(SignatureCache::default);

impl Default for SignatureCache {
    fn default() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }
}

impl SignatureCache {
    /// How many verified signatures to remember.
    ///
    /// Each entry costs 32 bytes of digest plus the set and queue overhead, so
    /// the whole cache stays well under 100 KB. That is deliberately far
    /// smaller than a server-side cache would be: the point is to hold the few
    /// subnet delegation keys in play, and a canister pays for every page it
    /// touches.
    pub const DEFAULT_CAPACITY: usize = 512;

    /// Creates a FIFO cache limited to `capacity` entries (at least one).
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            inner: Mutex::new(Inner {
                entries: HashSet::with_capacity(capacity),
                order: VecDeque::with_capacity(capacity),
            }),
        }
    }

    /// The cache used by [`verify_certificate`](crate::verify_certificate).
    pub fn global() -> &'static Self {
        &GLOBAL
    }

    /// Hashes the verification inputs into a cache key.
    pub fn entry(public_key: &[u8], signature: &[u8], msg: &[u8]) -> SignatureCacheEntry {
        let mut hasher = Sha256::new();
        // Length-prefix each field so that concatenations of different inputs
        // cannot collide onto the same key.
        for field in [public_key, signature, msg] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        SignatureCacheEntry(hasher.finalize().into())
    }

    pub fn contains(&self, entry: &SignatureCacheEntry) -> bool {
        self.lock().entries.contains(entry)
    }

    /// Records a signature as verified.
    ///
    /// # Warning
    /// Only insert an entry whose signature has actually been verified: a
    /// hit short-circuits verification entirely.
    pub fn insert(&self, entry: SignatureCacheEntry) {
        let mut inner = self.lock();
        if !inner.entries.insert(entry) {
            return;
        }
        inner.order.push_back(entry);
        while inner.order.len() > self.capacity {
            if let Some(evicted) = inner.order.pop_front() {
                inner.entries.remove(&evicted);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|err| err.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hit_requires_all_three_inputs_to_match() {
        let cache = SignatureCache::default();
        let entry = SignatureCache::entry(b"pk", b"sig", b"msg");
        assert!(!cache.contains(&entry));

        cache.insert(entry);
        assert!(cache.contains(&entry));

        for other in [
            SignatureCache::entry(b"pk2", b"sig", b"msg"),
            SignatureCache::entry(b"pk", b"sig2", b"msg"),
            SignatureCache::entry(b"pk", b"sig", b"msg2"),
        ] {
            assert!(!cache.contains(&other));
        }
    }

    #[test]
    fn field_lengths_are_bound_into_the_key() {
        // Without length prefixes these two triples would hash identically.
        assert_ne!(
            SignatureCache::entry(b"ab", b"c", b"d"),
            SignatureCache::entry(b"a", b"bc", b"d")
        );
    }

    #[test]
    fn the_cache_evicts_instead_of_growing_without_bound() {
        let cache = SignatureCache::default();
        let first = SignatureCache::entry(b"pk", b"sig", &0u32.to_be_bytes());
        for i in 0..=SignatureCache::DEFAULT_CAPACITY {
            cache.insert(SignatureCache::entry(
                b"pk",
                b"sig",
                &(i as u32).to_be_bytes(),
            ));
        }

        let inner = cache.lock();
        assert_eq!(inner.order.len(), SignatureCache::DEFAULT_CAPACITY);
        assert_eq!(inner.entries.len(), SignatureCache::DEFAULT_CAPACITY);
        // The oldest entry is the one that made room.
        assert!(!inner.entries.contains(&first));
    }

    #[test]
    fn reinserting_an_entry_does_not_consume_capacity_twice() {
        let cache = SignatureCache::default();
        let entry = SignatureCache::entry(b"pk", b"sig", b"msg");
        cache.insert(entry);
        cache.insert(entry);

        let inner = cache.lock();
        assert_eq!(inner.order.len(), 1);
        assert_eq!(inner.entries.len(), 1);
    }

    #[test]
    fn custom_capacity_controls_fifo_eviction() {
        for capacity in [0, 1, 1024] {
            let cache = SignatureCache::with_capacity(capacity);
            let limit = capacity.max(1);
            let first = SignatureCache::entry(b"pk", b"sig", &0usize.to_be_bytes());
            for i in 0..limit {
                cache.insert(SignatureCache::entry(b"pk", b"sig", &i.to_be_bytes()));
            }
            assert!(cache.contains(&first));
            let last = SignatureCache::entry(b"pk", b"sig", &limit.to_be_bytes());
            cache.insert(last);
            assert!(!cache.contains(&first));
            assert!(cache.contains(&last));
            assert_eq!(cache.lock().entries.len(), limit);
        }
    }
}
