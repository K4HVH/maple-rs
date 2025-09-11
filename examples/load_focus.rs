use maple::{Maple, Result};
use std::fs;
use std::path::Path;

fn main() -> Result<()> {
    let focus_path = Path::new("test/focus/focus.exe");

    if !focus_path.exists() {
        eprintln!("focus.exe not found in test/focus directory");
        return Ok(());
    }

    // Check if all the required DLLs are present in the focus directory
    let dll_files = [
        "abseil_dll.dll",
        "jpeg62.dll", 
        "libcrypto-3-x64.dll",
        "liblzma.dll",
        "libpng16.dll",
        "libprotobuf.dll",
        "libsharpyuv.dll",
        "libwebp.dll",
        "libwebpdecoder.dll",
        "opencv_core4.dll",
        "opencv_dnn4.dll", 
        "opencv_highgui4.dll",
        "opencv_imgcodecs4.dll",
        "opencv_imgproc4.dll",
        "opencv_videoio4.dll",
        "tiff.dll",
        "zlib1.dll"
    ];

    println!("Copying required DLLs to current directory...");
    for dll in &dll_files {
        let dll_path = Path::new("test/focus").join(dll);
        if dll_path.exists() {
            if let Err(e) = fs::copy(&dll_path, dll) {
                eprintln!("Warning: Failed to copy {}: {}", dll, e);
            } else {
                println!("Copied {}", dll);
            }
        } else {
            eprintln!("Warning: {} not found", dll);
        }
    }

    println!("\nLoading focus.exe from memory...");
    let focus_data = fs::read(focus_path)?;
    
    println!("Creating memory module...");
    println!("Focus.exe size: {} bytes", focus_data.len());
    
    match Maple::load_executable_from_memory(&focus_data) {
        Ok(module) => {
            println!("Successfully loaded focus.exe into memory");
            println!("Base address: {:p}", module.base_address());
            println!("Size: {} bytes", module.size());
            println!("Is loaded: {}", module.is_loaded());

            println!("\nExecuting GUI application entry point...");
            println!("Note: This will launch the focus.exe GUI application from memory!");
            
            match module.execute_entry_point() {
                Ok(_) => println!("Entry point executed successfully (GUI should have appeared)"),
                Err(e) => eprintln!("Failed to execute entry point: {}", e),
            }
        }
        Err(e) => {
            eprintln!("Failed to load focus.exe: {}", e);
        }
    }

    // Clean up copied DLLs
    println!("\nCleaning up copied DLLs...");
    for dll in &dll_files {
        if Path::new(dll).exists() {
            let _ = fs::remove_file(dll);
        }
    }

    Ok(())
}