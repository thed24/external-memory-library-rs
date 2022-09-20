use anyhow::{bail, Result};
use cxx::let_cxx_string;

use crate::bridge;

use super::memory::Memory;

pub struct MemoryBuilder {
    process_id: usize,
    base_address: usize,
}

impl MemoryBuilder {
    pub fn build(self) -> Result<Memory> {
        unsafe {
            match bridge::initialize() {
                true => Ok(Memory {
                    process_id: self.process_id,
                    base_address: self.base_address,
                }),
                false => bail!("Failed to initialize driver"),
            }
        }
    }
}

pub struct MemoryConfigurer;

impl MemoryConfigurer {
    pub fn default() -> Self {
        Self {}
    }

    pub fn configure(self, process_name: &str, module: &str, offset: usize) -> MemoryBuilder {
        let_cxx_string!(c_process_name = process_name);
        let_cxx_string!(c_module = module);

        unsafe {
            let process_id = bridge::get_process_by_name(&c_process_name);
            let base_address = bridge::get_module_base_address(process_id, &c_module, offset);

            MemoryBuilder {
                base_address,
                process_id,
            }
        }
    }
}
