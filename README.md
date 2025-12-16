# RunPE

Binary protection mechanism that runs an embedded PE image in memory without writing it to disk. Useful for protecting game binaries, implementing anti-cheat systems, and DRM solutions.

## Features

- **32-bit and 64-bit Support**: Works with both x86 and x64 PE binaries
- **Windows 10/11 Compatible**: Tested on latest Windows versions
- **File-less Execution**: Runs embedded PE without disk writes
- **Proper Error Handling**: Returns specific error codes for debugging
- **Resource Cleanup**: Properly releases handles and memory

## Requirements

- Windows 10 or Windows 11
- Visual Studio 2019 or later (or compatible compiler)
- Python 3.6+ (for the binary converter tool)

## Files

| File | Description |
|------|-------------|
| `Main.cpp` | Core RunPE implementation with 32/64-bit support |
| `bin_to_carray.py` | Python tool to convert binaries to C arrays |

## Building

### For 64-bit Payloads
```
cl /EHsc /D_WIN64 Main.cpp /link /MACHINE:X64 /OUT:RunPE64.exe
```

### For 32-bit Payloads
```
cl /EHsc Main.cpp /link /MACHINE:X86 /OUT:RunPE32.exe
```

### Visual Studio
1. Create a new Windows Desktop Application project
2. Set platform to x64 (for 64-bit) or x86 (for 32-bit)
3. Add Main.cpp to the project
4. Build

**Important**: The loader architecture must match the payload architecture.

## Usage

### Step 1: Convert Your Binary

```bash
# Convert a 64-bit binary
python bin_to_carray.py your_game.exe payload.h --name rawData

# Convert a 32-bit binary
python bin_to_carray.py your_game_x86.exe payload.h --name rawData
```

The script will automatically detect and display the binary's architecture.

### Step 2: Include the Generated Array

Replace the `rawData` array in `Main.cpp` with the contents of the generated header file.

### Step 3: Build and Run

Build the project with the matching architecture and run the resulting executable.

## Binary Converter Options

```
python bin_to_carray.py <input> [output] [options]

Arguments:
  input              Input binary file path
  output             Output file path (optional, prints to stdout)

Options:
  -n, --name NAME    Variable name for the array (default: rawData)
  -b, --bytes N      Bytes per line in output (default: 16)

Examples:
  bin_to_carray.py game.exe                    # Print to stdout
  bin_to_carray.py game.exe game_data.h        # Write to file
  bin_to_carray.py game.exe -n gamePayload     # Custom variable name
```

## Error Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Invalid DOS signature |
| 2 | Invalid PE signature |
| 3 | Architecture mismatch |
| 4 | Failed to get module path |
| 5 | Failed to create process |
| 6 | Failed to allocate context memory |
| 7 | Failed to get thread context |
| 8 | Failed to read original image base |
| 9 | Failed to allocate memory in target |
| 10 | Failed to write PE headers |
| 11 | Failed to update PEB ImageBase |
| 12 | Failed to set thread context |
| 13 | Failed to resume thread |

## Technical Details

### Windows APIs Used

All APIs are standard Windows functions available since Windows XP and fully supported on Windows 10/11:

- `CreateProcessA` - Process creation
- `VirtualAlloc` / `VirtualAllocEx` - Memory allocation
- `VirtualFree` / `VirtualFreeEx` - Memory deallocation
- `GetThreadContext` / `SetThreadContext` - Thread context manipulation
- `ReadProcessMemory` / `WriteProcessMemory` - Cross-process memory operations
- `ResumeThread` - Thread execution control
- `GetModuleFileNameA` - Module path retrieval

### Architecture Differences

| Aspect | 32-bit (x86) | 64-bit (x64) |
|--------|--------------|--------------|
| PEB Register | EBX | RDX |
| Entry Point Register | EAX | RCX |
| ImageBase Offset in PEB | +0x08 | +0x10 |
| NT Headers Type | IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64 |
| Machine Type | 0x014C (i386) | 0x8664 (AMD64) |

## Security Considerations

This tool is intended for legitimate binary protection purposes:
- Game anti-cheat systems
- DRM implementation
- Binary asset protection
- Software licensing enforcement

Always ensure you have proper authorization to protect/embed any binaries.

## License

MIT License - See LICENSE file for details.
