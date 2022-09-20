use anyhow::Result;
use std::marker::PhantomData;

use crate::utilities::memory::Memory;

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct Pointer<T: Sized + 'static> {
    pub address: usize,
    phantom_data: PhantomData<fn() -> T>,
}

impl<T: Sized + 'static> Pointer<T> {
    pub const NULL: Pointer<T> = Pointer {
        address: 0,
        phantom_data: PhantomData,
    };

    #[inline]
    pub fn deref(&self, memory: &Memory) -> Result<T> {
        memory.read::<T>(self.address)
    }

    #[inline]
    pub fn overwrite(&self, memory: &Memory, value: usize, offset: Option<usize>) -> Result<()> {
        let address = if let Some(offset) = offset {
            self.address + offset
        } else {
            self.address
        };

        memory.write_ptr(address, value);
        Ok(())
    }
}

impl<T: Sized + 'static> From<usize> for Pointer<T> {
    #[inline]
    fn from(address: usize) -> Self {
        Pointer {
            address,
            phantom_data: PhantomData,
        }
    }
}
