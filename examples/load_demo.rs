use maple_rs::{Maple, Result};
use std::fs;
use std::path::Path;

fn main() -> Result<()> {
    let demo_path = Path::new("test/demo.exe");
    let dll_path = Path::new("test/makcu-cpp.dll");
    let focus_dll_path = Path::new("test/focus/focus.dll");

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

    // Demo application DLL loading if focus.dll exists
    if focus_dll_path.exists() {
        use std::env;

        println!("\nTesting application DLL loading with focus.dll...");

        // Change to focus directory temporarily for dependency resolution
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let focus_dir = focus_dll_path.parent().unwrap();
        env::set_current_dir(focus_dir).expect("Failed to change to focus directory");

        let focus_dll_data = fs::read(focus_dll_path)?;
        match Maple::load_application_dll_from_memory(&focus_dll_data) {
            Ok(module) => {
                println!("Successfully loaded focus.dll as application DLL");
                println!("Base address: {:p}", module.base_address());
                println!("Size: {} bytes", module.size());

                println!("Executing application DLL (will run for 3 seconds)...");
                match module.execute_dll_application() {
                    Ok(_) => {
                        println!("Application DLL started successfully!");
                        std::thread::sleep(std::time::Duration::from_secs(3));
                    }
                    Err(e) => eprintln!("Failed to execute application DLL: {}", e),
                }
            }
            Err(e) => {
                eprintln!("Failed to load focus.dll as application DLL: {}", e);
            }
        }

        // Restore working directory
        env::set_current_dir(&current_dir).expect("Failed to restore working directory");
    }

    // Clean up the copied DLL
    if Path::new("makcu-cpp.dll").exists() {
        println!("\nCleaning up copied DLL...");
        if let Err(e) = fs::remove_file("makcu-cpp.dll") {
            eprintln!("Warning: Failed to clean up makcu-cpp.dll: {}", e);
        } else {
            println!("Cleaned up makcu-cpp.dll");
        }
    }

    Ok(())
}
