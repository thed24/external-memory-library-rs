#![feature(strict_provenance)]

#[cxx::bridge(namespace = "Driver")]
pub mod bridge {

    unsafe extern "C++" {
        include!("external-memory-lib/Driver.h");

        fn read_memory(process_id: usize, address: usize, buffer: usize, size: usize) -> bool;
        fn write(process_id: usize, address: usize, buffer: &usize);
        fn get_module_base_address(process_id: usize, name: &CxxString, offset: usize) -> usize;
        fn get_process_by_name(process_name: &CxxString) -> usize;
        fn initialize() -> bool;
    }
}

pub mod types;
pub mod utilities;
