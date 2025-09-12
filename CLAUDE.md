# Maple-rs: In-Memory Executable Loading Library

## Overview

Maple-rs is a Rust library that provides functionality for loading Windows PE executables and DLLs directly from memory, without needing to write them to disk first. This is a Rust replacement for the C memorymodule library, designed with multiplatform support in mind (Windows implemented, Linux placeholder provided).

## Key Features

- **In-Memory Loading**: Load PE executables (.exe) and dynamic libraries (.dll) directly from memory buffers
- **Full PE Support**: Complete PE parsing, section handling, import resolution, and relocation processing
- **Native Execution**: Applications run exactly as if they were loaded from disk
- **Memory Management**: Proper memory allocation, protection, and cleanup
- **Import Resolution**: Automatic resolution of external dependencies
- **Symbol Resolution**: Support for both named and ordinal-based symbol lookup
- **Cross-Platform Ready**: Windows implementation complete, Linux placeholder for future development

## Architecture

### Core Components

1. **Memory Module Trait** (`memory_module.rs`): Defines the interface for memory-loaded modules
2. **PE Parser** (`pe.rs`): Handles PE format parsing and validation
3. **Windows Implementation** (`windows.rs`): Platform-specific memory loading for Windows
4. **Linux Placeholder** (`linux.rs`): Stub implementation for future Linux support
5. **Error Handling** (`error.rs`): Comprehensive error types for all operations

### Project Structure

```
maple-rs/
├── src/
│   ├── lib.rs              # Main library interface
│   ├── error.rs            # Error definitions
│   ├── memory_module.rs    # Core trait and builder
│   ├── pe.rs              # PE format parser
│   ├── windows.rs         # Windows implementation
│   └── linux.rs           # Linux placeholder
├── examples/
│   └── load_demo.rs       # Example usage
├── test/                  # Test executables
│   ├── demo.exe          # Console application
│   ├── makcu-cpp.dll     # Library dependency
│   └── focus/            # GUI application with dependencies
└── Cargo.toml            # Project configuration
```

## Usage

### Basic Usage

```rust
use maple::{Maple, Result};
use std::fs;

fn main() -> Result<()> {
    // Load executable from memory
    let data = fs::read("program.exe")?;
    let module = Maple::load_executable_from_memory(&data)?;
    
    // Execute the program
    module.execute_entry_point()?;
    
    Ok(())
}
```

### Advanced Usage with Options

```rust
use maple::{MemoryModuleBuilder, Result};
use std::fs;

fn main() -> Result<()> {
    let data = fs::read("library.dll")?;
    
    let module = MemoryModuleBuilder::new()
        .resolve_imports(true)
        .process_relocations(true) 
        .call_dll_main(true)
        .load_from_memory(&data)?;
    
    // Use the loaded library
    let proc_addr = module.get_proc_address("MyFunction")?;
    
    Ok(())
}
```

## Implementation Details

### PE Parsing

The PE parser handles:
- DOS header validation
- NT headers parsing
- Optional header (64-bit only)
- Section header parsing
- Data directory access
- RVA to file offset mapping

### Memory Management

Windows implementation uses:
- `VirtualAlloc` for memory reservation and commitment
- `VirtualProtect` for setting appropriate section permissions
- `VirtualFree` for cleanup
- Proper handling of section characteristics (read/write/execute)

### Import Resolution

The import resolver:
- Parses import directory
- Loads required DLLs using `LoadLibraryW`
- Resolves function addresses using `GetProcAddress`
- Updates Import Address Table (IAT)
- Supports both named and ordinal imports

### Relocation Processing

The relocation processor:
- Handles base address differences
- Processes relocation blocks
- Supports multiple relocation types:
  - `IMAGE_REL_BASED_DIR64` (64-bit addresses)
  - `IMAGE_REL_BASED_HIGHLOW` (32-bit addresses)

## Testing

The library has been tested with:
- **demo.exe**: A console application that depends on makcu-cpp.dll
- **makcu-cpp.dll**: A library dependency
- **focus.exe**: A GUI application with multiple dependencies

### Expected Output

Running the demo application produces:
```
MAKCU C++ High-Performance Library Demo
=======================================

Scanning for MAKCU devices...
No MAKCU devices found. Please connect your device and try again.
```

This matches exactly the output when running the executable normally from disk.

## Dependencies

- `thiserror`: For error handling
- `memoffset`: For memory layout calculations
- `winapi`: Windows API bindings (Windows only)
- `libc`: POSIX API bindings (Linux placeholder)

## Platform Support

### Windows (Implemented)
- Full PE parsing and loading
- Import resolution with Windows DLLs
- Memory protection and section handling
- Entry point execution
- DLL initialization (DllMain)

### Linux (Placeholder)
- Stub implementation returns platform not supported errors
- Ready for future ELF loading implementation
- Would handle shared objects (.so files)

## Security Considerations

- Memory is properly allocated and protected
- No disk writes required (stealth loading)
- Import validation prevents malicious DLL injection
- Proper cleanup prevents memory leaks
- PE validation prevents malformed executables

## Error Handling

Comprehensive error types:
- `InvalidPEFormat`: PE parsing errors
- `MemoryAllocation`: Memory management failures
- `ImportResolution`: Dependency loading issues
- `RelocationFailed`: Address fixup problems
- `SymbolNotFound`: Missing function exports
- `ExecutionFailed`: Runtime execution errors
- `PlatformNotSupported`: Unsupported platforms

## Performance

The library is designed for:
- Fast loading times
- Minimal memory overhead
- Efficient symbol resolution
- Proper memory layout optimization

## Future Enhancements

1. **Linux Support**: Complete ELF implementation
2. **Export Directory**: Support for querying module exports
3. **Thread Safety**: Multi-threaded loading support
4. **Debugging Support**: Integration with debugging APIs
5. **Injection Features**: Process injection capabilities

## Examples

The `examples/load_demo.rs` file demonstrates:
- Loading executables from memory
- Loading libraries from memory
- Error handling
- Execution flow

Run the example with:
```bash
cargo run --example load_demo
```

## License

GPL-3.0 License - See LICENSE file for details.

## Contributing

This library is designed to be a drop-in replacement for the C memorymodule library but with modern Rust safety and performance characteristics.