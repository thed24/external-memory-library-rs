#![feature(strict_provenance)]
use anyhow::{bail, Result};
use bincode::{
    config::{Configuration, Fixint, LittleEndian, NoLimit, WriteFixedArrayLength},
    Encode,
};
use cxx::let_cxx_string;

#[cxx::bridge(namespace = "Driver")]
mod ffi {
    unsafe extern "C++" {
        include!("external_memory_lib/Include/include/Driver.h");

        fn read_memory(process_id: usize, address: usize, buffer: usize, size: usize) -> bool;
        fn write(process_id: usize, address: usize, buffer: &usize);
        fn get_module_base_address(process_id: usize, name: &CxxString, offset: usize) -> usize;
        fn get_process_by_name(process_name: &CxxString) -> usize;
        fn initialize() -> bool;
    }
}

pub struct MemoryConfigurer;

impl MemoryConfigurer {
    pub fn default() -> Self {
        Self {}
    }
}

impl MemoryConfigurer {
    pub fn configure(self, process_name: &str, module: &str, offset: usize) -> MemoryBuilder {
        let_cxx_string!(c_process_name = process_name);
        let_cxx_string!(c_module = module);

        let process_id = ffi::get_process_by_name(&c_process_name);
        let base_address = ffi::get_module_base_address(process_id, &c_module, offset);

        MemoryBuilder {
            base_address,
            process_id,
        }
    }
}

pub struct MemoryBuilder {
    process_id: usize,
    base_address: usize,
}

impl MemoryBuilder {
    pub fn build(self) -> Result<Memory> {
        match ffi::initialize() {
            true => Ok(Memory {
                process_id: self.process_id,
                base_address: self.base_address,
            }),
            false => bail!("Failed to initialize memory"),
        }
    }
}

pub struct Memory {
    pub process_id: usize,
    pub base_address: usize,
}

impl Memory {
    pub fn read_bytes(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        let buffer = vec![0; size];

        let read = ffi::read_memory(self.process_id, address, buffer.as_ptr().addr(), size);

        if read {
            Ok(buffer)
        } else {
            bail!(
                "Failed to read bytes with size {} from address {:#01x}",
                size,
                address
            )
        }
    }

    pub fn read_bytes_into_buffer(&self, address: usize, buffer: &mut [u8]) -> Result<()> {
        let read = ffi::read_memory(
            self.process_id,
            address,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
        );

        if read {
            Ok(())
        } else {
            bail!("Failed to read memory into buffer.")
        }
    }

    pub fn read_unity_string(&self, address: usize) -> Result<String> {
        let multiplier = std::mem::size_of::<u16>() as i32;
        let length = self.read::<i32>(address + 0x10)? * multiplier;
        let string = self
            .read_string(address + 0x14, length as usize)?
            .replace('\0', "");

        Ok(string)
    }

    pub fn read_string(&self, address: usize, buffer_size: usize) -> Result<String> {
        let buffer = vec![0; buffer_size];

        let read = ffi::read_memory(
            self.process_id,
            address,
            buffer.as_ptr().addr(),
            buffer.len(),
        );

        if read {
            let string = std::str::from_utf8(&buffer);
            match string {
                Ok(string) => Ok(string.to_string()),
                Err(err) => bail!("Failed to parse string: {}", err),
            }
        } else {
            bail!("Failed to read string.")
        }
    }

    pub fn read<T: bincode::Decode>(&self, address: usize) -> Result<T> {
        let bytes = self.read_bytes(address, std::mem::size_of::<T>());

        if let Ok(bytes) = bytes {
            let byte_array = bytes.as_slice();
            let res = bincode::decode_from_slice::<
                T,
                Configuration<LittleEndian, Fixint, WriteFixedArrayLength, NoLimit>,
            >(byte_array, bincode::config::legacy());
            if let Ok(res) = res {
                Ok(res.0)
            } else {
                bail!("Failed to decode bytes.")
            }
        } else {
            bail!("Failed to read by type: {}", std::any::type_name::<T>())
        }
    }

    pub fn read_sequence(&self, address: usize, offsets: Vec<usize>) -> Result<usize> {
        let mut current_address = address;

        for offset in offsets {
            let result = self.read::<usize>(current_address + offset);
            if let Ok(value) = result {
                current_address = value;
            } else {
                bail!("Failed to read sequence at offset: {:#01x}", offset);
            }
        }

        Ok(current_address)
    }

    pub fn write_by_type<T: Encode>(&self, address: usize, value: T) -> Result<()> {
        let size = std::mem::size_of::<T>();
        let mut vec = vec![0_u8; size];
        let buffer = vec.as_mut_slice();

        bincode::encode_into_slice::<
            T,
            Configuration<LittleEndian, Fixint, WriteFixedArrayLength, NoLimit>,
        >(value, buffer, bincode::config::legacy())?;

        self.write(address, buffer.as_ptr().addr());
        Ok(())
    }

    pub fn write(&self, address: usize, value: usize) {
        ffi::write(self.process_id, address, &value);
    }
}
