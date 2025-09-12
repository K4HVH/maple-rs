# 🍁 maple-rs

[![Crates.io](https://img.shields.io/crates/v/maple-rs.svg)](https://crates.io/crates/maple-rs)
[![Documentation](https://docs.rs/maple-rs/badge.svg)](https://docs.rs/maple-rs)
[![Build Status](https://github.com/K4HVH/maple-rs/workflows/CI/badge.svg)](https://github.com/K4HVH/maple-rs/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Rust library for loading Windows PE executables and DLLs directly from memory, without needing to write them to disk first. This is a modern, memory-safe Rust replacement for the C memorymodule library.

## Security Notice

This library enables loading and executing code from memory buffers. While this has legitimate uses such as:

- Dynamic code loading in game engines
- Plugin systems  
- Testing and debugging tools
- Memory-efficient application packaging

**Users are responsible for ensuring they only load trusted code and comply with all applicable laws and security policies.**

## Features

- 🔹 **In-Memory Loading**: Load PE executables (.exe) and libraries (.dll) directly from memory
- 🔹 **Application DLL Support**: Execute applications compiled as DLLs with proper threading
- 🔹 **Full PE Support**: Complete PE parsing, import resolution, and relocation processing  
- 🔹 **Native Execution**: Code runs exactly as if loaded from disk
- 🔹 **Memory Safety**: Proper memory management with automatic cleanup
- 🔹 **Cross-Platform Ready**: Windows implementation complete, Linux planned
- 🔹 **Zero-Copy**: Efficient memory usage with minimal overhead

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
maple-rs = "0.1.0"
```

### Basic Usage

```rust
use maple_rs::{Maple, Result};
use std::fs;

fn main() -> Result<()> {
    // Load an executable from memory
    let data = fs::read("program.exe")?;
    let module = Maple::load_executable_from_memory(&data)?;
    
    // Execute the program's entry point
    module.execute_entry_point()?;
    
    Ok(())
}
```

### Loading Regular DLLs

```rust
use maple_rs::{MemoryModuleBuilder, Result};
use std::fs;

fn main() -> Result<()> {
    let data = fs::read("library.dll")?;
    
    let module = MemoryModuleBuilder::new()
        .resolve_imports(true)
        .process_relocations(true)
        .call_dll_main(true)
        .load_from_memory(&data)?;
    
    // Get a function from the loaded library
    let function = module.get_proc_address("MyFunction")?;
    
    Ok(())
}
```

### Loading Application DLLs

Application DLLs are applications that have been compiled as DLL files instead of executables. They typically start a thread in `DllMain` to run the application logic.

```rust
use maple_rs::{Maple, Result};
use std::fs;

fn main() -> Result<()> {
    // Load an application DLL (like focus.dll)
    let data = fs::read("app.dll")?;
    let module = Maple::load_application_dll_from_memory(&data)?;
    
    // Execute the application
    module.execute_dll_application()?;
    
    // Application runs in background thread...
    std::thread::sleep(std::time::Duration::from_secs(5));
    
    Ok(())
}
```

### Manual Control with Builder Pattern

For advanced control over application DLL loading:

```rust
use maple_rs::{MemoryModuleBuilder, Result};
use std::fs;

fn main() -> Result<()> {
    let data = fs::read("app.dll")?;
    
    let module = MemoryModuleBuilder::new()
        .resolve_imports(true)
        .process_relocations(true)
        .call_dll_main(false)        // Don't auto-call DllMain
        .is_application_dll(true)     // Mark as application DLL
        .load_from_memory(&data)?;
    
    // Manually execute when ready
    module.execute_dll_application()?;
    
    Ok(())
}
```

## API Reference

### Main Entry Points

- `Maple::load_executable_from_memory(data)` - Load a standard executable
- `Maple::load_library_from_memory(data)` - Load a standard DLL/library  
- `Maple::load_application_dll_from_memory(data)` - Load an application DLL

### MemoryModule Trait Methods

- `execute_entry_point()` - Execute an executable's entry point
- `execute_dll_application()` - Execute an application DLL (starts thread in DllMain)
- `call_dll_entry_point(reason)` - Manually call DllMain with specific reason
- `get_proc_address(name)` - Get function address by name
- `get_proc_address_ordinal(ordinal)` - Get function address by ordinal

### Builder Options

- `resolve_imports(bool)` - Enable/disable import resolution
- `process_relocations(bool)` - Enable/disable relocation processing
- `call_dll_main(bool)` - Auto-call DllMain on load
- `is_application_dll(bool)` - Mark as application DLL
- `ignore_missing_imports(bool)` - Continue loading with missing imports

## Documentation

Comprehensive API documentation is available on [docs.rs](https://docs.rs/maple-rs).

## Platform Support

| Platform | Status | Features |
|----------|--------|----------|
| Windows | ✅ Complete | Full PE parsing, import resolution, memory protection, application DLLs |
| Linux | 🔄 Planned | ELF support planned for future release |
| macOS | 🔄 Planned | Mach-O support planned for future release |

## Error Handling

All operations return a `Result<T, MapleError>` with detailed error information:

```rust
use maple_rs::{Maple, MapleError};

match Maple::load_executable_from_memory(&data) {
    Ok(module) => {
        // Successfully loaded
    },
    Err(MapleError::InvalidPEFormat(msg)) => {
        eprintln!("Invalid PE file: {}", msg);
    },
    Err(MapleError::MemoryAllocation(msg)) => {
        eprintln!("Memory allocation failed: {}", msg);
    },
    Err(MapleError::ImportResolution(msg)) => {
        eprintln!("Failed to resolve imports: {}", msg);
    },
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

## Architecture

``` bash
maple-rs/
├── src/
│   ├── lib.rs              # Main library interface
│   ├── error.rs            # Error definitions  
│   ├── memory_module.rs    # Core trait and builder
│   ├── pe.rs              # PE format parser
│   ├── windows.rs         # Windows implementation
│   └── linux.rs           # Linux placeholder
├── examples/              # Usage examples
├── tests/                # Integration tests
└── .github/workflows/    # CI/CD pipeline
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the GNU GPLv3 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the original [MemoryModule](https://github.com/fancycode/MemoryModule) C library
