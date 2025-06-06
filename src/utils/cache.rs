//! Cache Implementation
//! Author: kartik4091
//! Created: 2025-06-03 09:17:37 UTC

use super::*;
use std::{
    sync::Arc,
    time::{Duration, Instant},
    collections::{HashMap, LinkedList},
    hash::Hash,
};
use tokio::sync::RwLock;
use parking_lot::Mutex;

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum entries
    pub max_entries: usize,
    /// Entry TTL
    pub ttl: Duration,
    /// Enable metrics
    pub enable_metrics: bool,
    /// Cleanup interval
    pub cleanup_interval: Duration,
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry<V> {
    /// Value
    value: V,
    /// Creation time
    created: Instant,
    /// Last access time
    last_access: Instant,
    /// Access count
    access_count: u64,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total entries
    pub total_entries: usize,
    /// Hit count
    pub hits: u64,
    /// Miss count
    pub misses: u64,
    /// Eviction count
    pub evictions: u64,
    /// Memory usage
    pub memory_usage: usize,
}

/// Cache implementation
pub struct Cache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Cache configuration
    config: Arc<CacheConfig>,
    /// Cache entries
    entries: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    /// LRU list
    lru: Arc<Mutex<LinkedList<K>>>,
    /// Statistics
    stats: Arc<RwLock<CacheStats>>,
    /// Metrics
    metrics: Arc<Metrics>,
}

impl<K, V> Cache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Creates a new cache instance
    pub fn new(config: CacheConfig) -> Self {
        let cache = Self {
            config: Arc::new(config),
            entries: Arc::new(RwLock::new(HashMap::new())),
            lru: Arc::new(Mutex::new(LinkedList::new())),
            stats: Arc::new(RwLock::new(CacheStats::default())),
            metrics: Arc::new(Metrics::new()),
        };

        // Start cleanup task
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(cache_clone.config.cleanup_interval).await;
                if let Err(e) = cache_clone.cleanup().await {
                    error!("Cache cleanup error: {}", e);
                }
            }
        });

        cache
    }

    /// Gets a value from cache
    #[instrument(skip(self))]
    pub async fn get(&self, key: &K) -> Option<V> {
        let start = Instant::now();
        let mut stats = self.stats.write().await;
        
        // Check cache
        let mut entries = self.entries.write().await;
        if let Some(entry) = entries.get_mut(key) {
            // Check TTL
            if start.duration_since(entry.created) > self.config.ttl {
                entries.remove(key);
                stats.evictions += 1;
                stats.misses += 1;
                None
            } else {
                // Update access time and count
                entry.last_access = start;
                entry.access_count += 1;

                // Update LRU
                let mut lru = self.lru.lock();
                lru.push_back(key.clone());
                if lru.len() > self.config.max_entries {
                    lru.pop_front();
                }

                stats.hits += 1;
                
                // Record metrics
                if self.config.enable_metrics {
                    let metrics = self.metrics.clone();
                    let duration = start.elapsed();
                    tokio::spawn(async move {
                        let _ = metrics.record_operation("cache_hit", duration).await;
                    });
                }

                Some(entry.value.clone())
            }
        } else {
            stats.misses += 1;
            
            // Record metrics
            if self.config.enable_metrics {
                let metrics = self.metrics.clone();
                let duration = start.elapsed();
                tokio::spawn(async move {
                    let _ = metrics.record_operation("cache_miss", duration).await;
                });
            }

            None
        }
    }

    /// Sets a value in cache
    #[instrument(skip(self, value))]
    pub async fn set(&self, key: K, value: V) -> Result<()> {
        let start = Instant::now();
        let mut entries = self.entries.write().await;
        
        // Check capacity
        if entries.len() >= self.config.max_entries {
            // Evict LRU entry
            let mut lru = self.lru.lock();
            if let Some(lru_key) = lru.pop_front() {
                entries.remove(&lru_key);
                let mut stats = self.stats.write().await;
                stats.evictions += 1;
            }
        }

        // Insert new entry
        entries.insert(key.clone(), CacheEntry {
            value,
            created: start,
            last_access: start,
            access_count: 0,
        });

        // Update LRU
        let mut lru = self.lru.lock();
        lru.push_back(key);

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_entries = entries.len();
        stats.memory_usage = std::mem::size_of_val(&*entries);

        // Record metrics
        if self.config.enable_metrics {
            let metrics = self.metrics.clone();
            let duration = start.elapsed();
            tokio::spawn(async move {
                let _ = metrics.record_operation("cache_set", duration).await;
            });
        }

        Ok(())
    }

    /// Removes a value from cache
    #[instrument(skip(self))]
    pub async fn remove(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.write().await;
        let entry = entries.remove(key)?;

        // Update LRU
        let mut lru = self.lru.lock();
        lru.retain(|k| k != key);

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.total_entries = entries.len();
        stats.memory_usage = std::mem::size_of_val(&*entries);

        Some(entry.value)
    }

    /// Clears the cache
    #[instrument(skip(self))]
    pub async fn clear(&self) -> Result<()> {
        let mut entries = self.entries.write().await;
        entries.clear();

        let mut lru = self.lru.lock();
        lru.clear();

        let mut stats = self.stats.write().await;
        *stats = CacheStats::default();

        Ok(())
    }

    /// Performs cache cleanup
    #[instrument(skip(self))]
    async fn cleanup(&self) -> Result<()> {
        let start = Instant::now();
        let mut entries = self.entries.write().await;
        let mut lru = self.lru.lock();
        let mut stats = self.stats.write().await;

        let mut expired = Vec::new();
        for (key, entry) in entries.iter() {
            if start.duration_since(entry.created) > self.config.ttl {
                expired.push(key.clone());
            }
        }

        for key in expired {
            entries.remove(&key);
            lru.retain(|k| k != &key);
            stats.evictions += 1;
        }

        stats.total_entries = entries.len();
        stats.memory_usage = std::mem::size_of_val(&*entries);

        // Record metrics
        if self.config.enable_metrics {
            let metrics = self.metrics.clone();
            let duration = start.elapsed();
            tokio::spawn(async move {
                let _ = metrics.record_operation("cache_cleanup", duration).await;
            });
        }

        Ok(())
    }

    /// Gets cache statistics
    #[instrument(skip(self))]
    pub async fn get_stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }
}

impl<K, V> Clone for Cache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            entries: self.entries.clone(),
            lru: self.lru.clone(),
            stats: self.stats.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            ttl: Duration::from_secs(3600), // 1 hour
            enable_metrics: true,
            cleanup_interval: Duration::from_secs(60), // 1 minute
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_operations() {
        let cache: Cache<String, i32> = Cache::new(CacheConfig::default());
        
        // Test set and get
        cache.set("key1".into(), 42).await.unwrap();
        assert_eq!(cache.get(&"key1".into()).await, Some(42));
        assert_eq!(cache.get(&"key2".into()).await, None);
        
        // Test removal
        assert_eq!(cache.remove(&"key1".into()).await, Some(42));
        assert_eq!(cache.get(&"key1".into()).await, None);
    }

    #[tokio::test]
    async fn test_cache_capacity() {
        let cache: Cache<String, i32> = Cache::new(CacheConfig {
            max_entries: 2,
            ..CacheConfig::default()
        });
        
        cache.set("key1".into(), 1).await.unwrap();
        cache.set("key2".into(), 2).await.unwrap();
        cache.set("key3".into(), 3).await.unwrap();
        
        // First key should be evicted
        assert_eq!(cache.get(&"key1".into()).await, None);
        assert_eq!(cache.get(&"key2".into()).await, Some(2));
        assert_eq!(cache.get(&"key3".into()).await, Some(3));
    }

    #[tokio::test]
    async fn test_cache_ttl() {
        let cache: Cache<String, i32> = Cache::new(CacheConfig {
            ttl: Duration::from_millis(100),
            cleanup_interval: Duration::from_millis(50),
            ..CacheConfig::default()
        });
        
        cache.set("key".into(), 42).await.unwrap();
        assert_eq!(cache.get(&"key".into()).await, Some(42));
        
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(cache.get(&"key".into()).await, None);
    }

    #[tokio::test]
    async fn test_cache_statistics() {
        let cache: Cache<String, i32> = Cache::new(CacheConfig::default());
        
        cache.set("key".into(), 42).await.unwrap();
        cache.get(&"key".into()).await;
        cache.get(&"nonexistent".into()).await;
        
        let stats = cache.get_stats().await;
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.total_entries, 1);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache: Cache<String, i32> = Cache::new(CacheConfig::default());
        
        cache.set("key1".into(), 1).await.unwrap();
        cache.set("key2".into(), 2).await.unwrap();
        
        cache.clear().await.unwrap();
        
        assert_eq!(cache.get(&"key1".into()).await, None);
        assert_eq!(cache.get(&"key2".into()).await, None);
        
        let stats = cache.get_stats().await;
        assert_eq!(stats.total_entries, 0);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let cache: Cache<String, i32> = Cache::new(CacheConfig::default());
        let cache_clone = cache.clone();
        
        let handle1 = tokio::spawn(async move {
            for i in 0..100 {
                cache.set(format!("key{}", i), i).await.unwrap();
            }
        });
        
        let handle2 = tokio::spawn(async move {
            for i in 0..100 {
                let _ = cache_clone.get(&format!("key{}", i)).await;
            }
        });
        
        handle1.await.unwrap();
        handle2.await.unwrap();
    }
          }
