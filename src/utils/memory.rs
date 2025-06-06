//! Memory utility functions for PDF anti-forensics
//! Created: 2025-06-03 16:42:36 UTC
//! Author: kartik4091

use std::alloc::{self, Layout};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, error, info, instrument, warn};

use crate::error::{Error, Result};

/// A tracking memory block allocator for secure memory
pub struct SecureAllocator {
    used: AtomicUsize,
    peak: AtomicUsize,
}

impl SecureAllocator {
    pub const fn new() -> Self {
        Self {
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    #[instrument]
    pub fn allocate(&self, size: usize, align: usize) -> Result<NonNull<u8>> {
        let layout = Layout::from_size_align(size, align).map_err(|e| Error::MemoryError(e.to_string()))?;
        let ptr = unsafe { alloc::alloc(layout) };
        if ptr.is_null() {
            error!("Failed to allocate {} bytes", size);
            return Err(Error::MemoryError("Allocation failed".into()));
        }
        self.used.fetch_add(size, Ordering::SeqCst);
        self.peak.fetch_max(self.used.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(unsafe { NonNull::new_unchecked(ptr) })
    }

    #[instrument]
    pub fn deallocate(&self, ptr: NonNull<u8>, size: usize, align: usize) -> Result<()> {
        let layout = Layout::from_size_align(size, align).map_err(|e| Error::MemoryError(e.to_string()))?;
        unsafe { alloc::dealloc(ptr.as_ptr(), layout); }
        self.used.fetch_sub(size, Ordering::SeqCst);
        Ok(())
    }

    #[instrument]
    pub fn zeroize(&self, ptr: NonNull<u8>, size: usize) {
        unsafe { ptr::write_bytes(ptr.as_ptr(), 0, size); }
        debug!("Zeroized {} bytes", size);
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.used.load(Ordering::Relaxed), self.peak.load(Ordering::Relaxed))
    }
}

/// Zeroize and free a given block of memory
#[instrument]
pub fn secure_free(ptr: NonNull<u8>, size: usize, align: usize, allocator: &SecureAllocator) -> Result<()> {
    allocator.zeroize(ptr, size);
    allocator.deallocate(ptr, size, align)
}

/// Reallocate memory block with zeroing old data
#[instrument]
pub fn secure_realloc(
    allocator: &SecureAllocator,
    old_ptr: NonNull<u8>,
    old_size: usize,
    new_size: usize,
    align: usize
) -> Result<NonNull<u8>> {
    let new_ptr = allocator.allocate(new_size, align)?;
    unsafe {
        ptr::copy_nonoverlapping(old_ptr.as_ptr(), new_ptr.as_ptr(), old_size.min(new_size));
        allocator.zeroize(old_ptr, old_size);
    }
    allocator.deallocate(old_ptr, old_size, align)?;
    Ok(new_ptr)
}
