//! TTL-respecting response cache.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Negative answers (NXDOMAIN / NODATA) are cached for at most this long.
const MAX_NEGATIVE_TTL: u32 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
}

#[derive(Debug, Clone)]
struct Entry {
    message: Message,
    stored: Instant,
    expires: Instant,
}

#[derive(Debug)]
pub struct DnsCache {
    entries: Mutex<HashMap<CacheKey, Entry>>,
    capacity: usize,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    pub fn new(capacity: usize, min_ttl: u32, max_ttl: u32) -> Self {
        DnsCache {
            entries: Mutex::new(HashMap::new()),
            capacity,
            min_ttl,
            max_ttl,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// TTL to cache a response for, or `None` if it must not be cached.
    pub fn cache_ttl(&self, msg: &Message) -> Option<u32> {
        if msg.metadata.truncation {
            return None;
        }
        let ttl = match msg.metadata.response_code {
            ResponseCode::NoError if !msg.answers.is_empty() => {
                msg.answers.iter().map(|r| r.ttl).min()?
            }
            ResponseCode::NoError | ResponseCode::NXDomain => {
                // Negative caching (RFC 2308): min(SOA TTL, SOA MINIMUM).
                let soa = msg.authorities.iter().find_map(|r| match &r.data {
                    RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
                    _ => None,
                });
                soa.unwrap_or(60).min(MAX_NEGATIVE_TTL)
            }
            _ => return None, // SERVFAIL, REFUSED, ... are never cached
        };
        let ttl = ttl.clamp(self.min_ttl, self.max_ttl);
        (ttl > 0).then_some(ttl)
    }

    pub fn insert(&self, key: CacheKey, message: Message) {
        if self.capacity == 0 {
            return;
        }
        let Some(ttl) = self.cache_ttl(&message) else {
            return;
        };
        let now = Instant::now();
        let mut entries = self.lock();
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            entries.retain(|_, e| e.expires > now);
            // Evict unless the purge freed real headroom; otherwise the next
            // insert would scan the whole cache again.
            if entries.len() >= self.capacity - self.capacity / 8 {
                // Nearly full: evict an arbitrary eighth. HashMap iteration
                // order is randomized, so this approximates random eviction
                // at O(1) amortized cost without LRU bookkeeping on hits.
                let victims: Vec<CacheKey> = entries
                    .keys()
                    .take(self.capacity / 8 + 1)
                    .cloned()
                    .collect();
                for k in victims {
                    entries.remove(&k);
                }
            }
        }
        entries.insert(
            key,
            Entry {
                message,
                stored: now,
                expires: now + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// Returns a cached response with TTLs reduced by the time spent in the
    /// cache.
    pub fn get(&self, key: &CacheKey) -> Option<Message> {
        let now = Instant::now();
        let mut entries = self.lock();
        let entry = entries.get(key)?;
        if entry.expires <= now {
            entries.remove(key);
            return None;
        }
        let elapsed = now.duration_since(entry.stored).as_secs() as u32;
        let mut msg = entry.message.clone();
        drop(entries);
        for r in msg
            .answers
            .iter_mut()
            .chain(msg.authorities.iter_mut())
            .chain(msg.additionals.iter_mut())
        {
            r.ttl = r.ttl.saturating_sub(elapsed).max(1);
        }
        Some(msg)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, Record};

    fn answer(ttl: u32) -> Message {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        m.add_answer(Record::from_rdata(
            Name::from_ascii("x.example.").unwrap(),
            ttl,
            RData::A(A::new(1, 2, 3, 4)),
        ));
        m
    }

    fn key(n: &str) -> CacheKey {
        CacheKey {
            name: n.into(),
            qtype: 1,
            qclass: 1,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    #[test]
    fn stores_and_expires() {
        let c = DnsCache::new(10, 0, 3600);
        c.insert(key("a"), answer(300));
        assert_eq!(c.get(&key("a")).unwrap().answers[0].ttl, 300);
        c.insert(key("b"), answer(0));
        assert!(c.get(&key("b")).is_none(), "zero TTL is not cached");
        let mut fail = answer(300);
        fail.metadata.response_code = ResponseCode::ServFail;
        c.insert(key("c"), fail);
        assert!(c.get(&key("c")).is_none());
    }

    #[test]
    fn bounded() {
        let c = DnsCache::new(16, 0, 3600);
        for i in 0..100 {
            c.insert(key(&i.to_string()), answer(300));
        }
        assert!(c.len() <= 16);
    }

    #[test]
    fn clamps_ttl() {
        let c = DnsCache::new(10, 60, 120);
        assert_eq!(c.cache_ttl(&answer(5)), Some(60));
        assert_eq!(c.cache_ttl(&answer(5000)), Some(120));
    }
}
