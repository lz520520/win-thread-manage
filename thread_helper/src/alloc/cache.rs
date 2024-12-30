use std::collections::{HashMap, HashSet};
use std::sync::{Arc,  RwLock};
use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE};

#[derive(Clone, Default, Debug)]
pub struct MemInfo {
    pub mem_base: usize,
    pub mem_size: usize,
}

#[derive(Clone,Default)]
pub struct AllocInfo {
    pub tid: usize,
    pub alloc_base: usize,
    pub alloc_size: usize,
    pub flallocationtype: VIRTUAL_ALLOCATION_TYPE,
    pub flprotect: PAGE_PROTECTION_FLAGS
}
pub struct MemAllocator {
    mem_cache_map: Arc<RwLock<HashMap<usize, MemInfo>>>, // key: plugin_address value: mem_size
    alloc_cache_map: Arc<RwLock<HashMap<usize, Vec<AllocInfo>>>>, // key: plugin_address value: alloc addresses
    thread_cache_map: Arc<RwLock<HashMap<usize, HashSet<usize>>>>, // key: plugin_address value: threads
}
impl MemAllocator {
    pub fn new() -> Self {
        MemAllocator {
            mem_cache_map: Arc::new(RwLock::new(HashMap::new())),
            alloc_cache_map: Arc::new(RwLock::new(HashMap::new())),
            thread_cache_map: Arc::new(RwLock::new(HashMap::new())),

        }
    }

    pub fn add_mem(&self, plugin_address: usize, info: &MemInfo) {
        self.mem_cache_map.write().unwrap().insert(plugin_address, info.clone());
    }

    pub fn del_mem(&self, plugin_address: usize) {
        self.mem_cache_map.write().unwrap().remove(&plugin_address);
    }
    /// 获取当前缓存的所有地址
    pub fn all_mem_values(&self) -> Vec<MemInfo> {
        let map = self.mem_cache_map.read().unwrap(); // 获取读锁
        map.values().cloned().collect()
    }

    pub fn add_alloc(&self, plugin_address: usize, info: &AllocInfo) {
        let mut map = self.alloc_cache_map.write().unwrap();
        map.entry(plugin_address).and_modify(|v| v.push(info.clone())).or_insert(vec![info.clone()]);
    }
    pub fn del_alloc(&self, plugin_address: usize) {
        self.alloc_cache_map.write().unwrap().remove(&plugin_address);
    }
    pub fn get_alloc(&self, plugin_address: usize) -> Option<Vec<AllocInfo>> {
        self.alloc_cache_map.read().unwrap().get(&plugin_address).cloned()
    }





    pub fn add_thread(&self, plugin_address: usize, tid: usize) {
        let mut map = self.thread_cache_map.write().unwrap();
        map.entry(plugin_address).and_modify(|v| {
            v.insert(tid);
        }).or_insert( HashSet::from_iter(vec![tid]));
    }
    pub fn del_thread(&self, plugin_address: usize) {
        self.thread_cache_map.write().unwrap().remove(&plugin_address);
    }
    pub fn get_thread(&self, plugin_address: usize) -> Option<HashSet<usize>> {
        self.thread_cache_map.read().unwrap().get(&plugin_address).cloned()
    }
}
lazy_static::lazy_static! {
    pub static ref MEM_ALLOC_CACHE: MemAllocator = MemAllocator::new();
}