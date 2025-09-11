use maple::{Maple, Result};
use std::fs;
use std::path::Path;

fn main() -> Result<()> {
    let demo_path = Path::new("test/demo.exe");
    let dll_path = Path::new("test/makcu-cpp.dll");

    if !demo_path.exists() {
        eprintln!("demo.exe not found in test directory");
        return Ok(());
    }

    if !dll_path.exists() {
        eprintln!("makcu-cpp.dll not found in test directory");
        return Ok(());
    }

    println!("First, copy makcu-cpp.dll to current directory so demo.exe can find it...");
    if dll_path.exists() {
        let _ = fs::copy(dll_path, "makcu-cpp.dll");
    }

    println!("Loading demo.exe from memory...");
    let demo_data = fs::read(demo_path)?;
    
    println!("Creating memory module...");
    match Maple::load_executable_from_memory(&demo_data) {
        Ok(module) => {
            println!("Successfully loaded demo.exe into memory");
            println!("Base address: {:p}", module.base_address());
            println!("Size: {} bytes", module.size());
            println!("Is loaded: {}", module.is_loaded());

            println!("Executing entry point...");
            match module.execute_entry_point() {
                Ok(_) => println!("Entry point executed successfully"),
                Err(e) => eprintln!("Failed to execute entry point: {}", e),
            }
        }
        Err(e) => {
            eprintln!("Failed to load demo.exe: {}", e);
        }
    }

    println!("\nLoading makcu-cpp.dll from memory...");
    let dll_data = fs::read(dll_path)?;
    
    match Maple::load_library_from_memory(&dll_data) {
        Ok(module) => {
            println!("Successfully loaded makcu-cpp.dll into memory");
            println!("Base address: {:p}", module.base_address());
            println!("Size: {} bytes", module.size());
            println!("Is loaded: {}", module.is_loaded());
        }
        Err(e) => {
            eprintln!("Failed to load makcu-cpp.dll: {}", e);
        }
    }

    Ok(())
}