use anyhow::{Ok, Result};

use external_memory_lib::utilities::builder::MemoryConfigurer;

pub fn main() -> Result<()> {
    let process_name = "csgo.exe";
    let process_module = "client.dll";
    let offset = 0xDEADBEEF;

    let memory_result = MemoryConfigurer::default()
        .configure(process_name, process_module, offset)
        .build();

    if memory_result.is_err() {
        eprintln!("Failed to initialize memory for process: {}", process_name);
        return Ok(());
    }

    let memory = memory_result.unwrap();

    let player_health_addr = 0x24;
    let player_health = memory.read::<u32>(player_health_addr)?;

    println!("Player health: {}", player_health);

    Ok(())
}
