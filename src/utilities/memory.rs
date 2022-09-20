use crate::bridge;
use anyhow::{bail, Context, Result};

pub struct Memory {
    pub process_id: usize,
    pub base_address: usize,
}

impl Memory {
    pub fn read_bytes(&self, address: usize, size: usize) -> Result<Vec<u8>> {
        let buffer = vec![0; size];

        unsafe {
            let read_successfully =
                bridge::read_memory(self.process_id, address, buffer.as_ptr().addr(), size);

            match read_successfully {
                true => Ok(buffer),
                false => bail!(
                    "Failed to read bytes with size {} from address {:#01x}",
                    size,
                    address
                ),
            }
        }
    }

    pub fn read_bytes_into_buffer(&self, address: usize, buffer: &mut [u8]) -> Result<()> {
        unsafe {
            let read_successfully = bridge::read_memory(
                self.process_id,
                address,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
            );

            match read_successfully {
                true => Ok(()),
                false => bail!(
                    "Failed to read into buffer {:#01x}",
                    buffer.as_mut_ptr().addr()
                ),
            }
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

        unsafe {
            let read_successfully = bridge::read_memory(
                self.process_id,
                address,
                buffer.as_ptr().addr(),
                buffer.len(),
            );

            match read_successfully {
                true => String::from_utf8(buffer).context("Failed to parse string from UTF8"),
                false => bail!("Failed to read string from address {:#01x}", address),
            }
        }
    }

    pub fn read<T>(&self, address: usize) -> Result<T> {
        unsafe {
            let bytes = self.read_bytes(address, std::mem::size_of::<T>());
            if let Ok(bytes) = bytes {
                let value = (bytes.as_ptr() as *const T).read();
                Ok(value)
            } else {
                // print err
                let err = bytes.err().unwrap();
                eprintln!("{}", err);
                bail!("Failed to read by type: {}", std::any::type_name::<T>())
            }
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

    pub fn write<T>(&self, address: usize, value: T) -> Result<()> {
        let size = std::mem::size_of::<T>();
        let mut vec = vec![0_u8; size];
        let buffer = vec.as_mut_slice();

        unsafe {
            std::ptr::write(buffer.as_mut_ptr() as *mut T, value);
        }

        self.write_ptr(address, buffer.as_ptr().addr());
        Ok(())
    }

    pub fn write_ptr(&self, address: usize, value: usize) {
        unsafe {
            bridge::write(self.process_id, address, &value);
        }
    }
}
