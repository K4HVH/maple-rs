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

### Advanced Usage with Builder Pattern

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

## Documentation

Comprehensive API documentation is available on [docs.rs](https://docs.rs/maple-rs).

## Platform Support

| Platform | Status | Features |
|----------|--------|----------|
| Windows | ✅ Complete | Full PE parsing, import resolution, memory protection |
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

```
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
