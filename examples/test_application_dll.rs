use maple_rs::{Maple, MemoryModuleBuilder};
use std::env;
use std::fs;

fn main() -> maple_rs::Result<()> {
    println!("Testing focus.dll as an application DLL...");

    // Change to the test/focus directory so dependencies are found
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let focus_dir = current_dir.join("test").join("focus");
    env::set_current_dir(&focus_dir).expect("Failed to change to focus directory");
    println!("Changed working directory to: {:?}", focus_dir);

    // Read the focus.dll file
    let dll_data = fs::read("focus.dll").expect("Failed to read focus.dll");
    println!("Loaded {} bytes from focus.dll", dll_data.len());

    // Test 1: Load as application DLL using the new convenient method
    println!("\nTest 1: Loading using Maple::load_application_dll_from_memory()...");
    match Maple::load_application_dll_from_memory(&dll_data) {
        Ok(module) => {
            println!("Successfully loaded focus.dll as application DLL!");
            println!("Base address: {:?}", module.base_address());
            println!("Size: {} bytes", module.size());

            println!("Executing DLL application...");
            match module.execute_dll_application() {
                Ok(()) => {
                    println!("DLL application started successfully!");
                    println!("Waiting 5 seconds to let the application run...");
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                Err(e) => {
                    println!("Failed to execute DLL application: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to load focus.dll as application DLL: {}", e);
        }
    }

    // Test 2: Load using the builder with application DLL settings
    println!("\nTest 2: Loading using MemoryModuleBuilder with application DLL settings...");
    match MemoryModuleBuilder::new()
        .resolve_imports(true)
        .process_relocations(true)
        .call_dll_main(false) // Don't auto-call DllMain
        .is_application_dll(true)
        .load_from_memory(&dll_data)
    {
        Ok(module) => {
            println!("Successfully loaded focus.dll with builder!");
            println!("Base address: {:?}", module.base_address());
            println!("Size: {} bytes", module.size());

            println!("Manually executing DLL application...");
            match module.execute_dll_application() {
                Ok(()) => {
                    println!("DLL application started successfully!");
                    println!("Waiting 5 seconds to let the application run...");
                    std::thread::sleep(std::time::Duration::from_secs(5));
                }
                Err(e) => {
                    println!("Failed to execute DLL application: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Failed to load focus.dll with builder: {}", e);
        }
    }

    // Restore working directory
    env::set_current_dir(&current_dir).expect("Failed to restore working directory");

    println!("\nTest completed!");
    Ok(())
}
