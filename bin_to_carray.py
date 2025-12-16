#!/usr/bin/env python3
"""
Binary to C Array Converter

Converts a PE binary file to a C-style unsigned char array
for embedding in the RunPE loader.

Usage:
    python bin_to_carray.py <input_file> [output_file] [--name varname]

Example:
    python bin_to_carray.py myapp.exe output.h --name rawData
"""

import sys
import os
import argparse


def convert_binary_to_carray(input_path, output_path=None, var_name="rawData", bytes_per_line=16):
    """
    Convert a binary file to a C-style unsigned char array.

    Args:
        input_path: Path to the input binary file
        output_path: Path to the output file (optional, prints to stdout if None)
        var_name: Name of the C array variable
        bytes_per_line: Number of bytes per line in output
    """
    # Read the binary file
    try:
        with open(input_path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {input_path}", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate PE signature
    if len(data) < 2 or data[0:2] != b'MZ':
        print("Warning: File does not appear to be a valid PE (missing MZ signature)", file=sys.stderr)

    # Detect architecture from PE header
    if len(data) > 64:
        e_lfanew = int.from_bytes(data[60:64], 'little')
        if len(data) > e_lfanew + 6:
            machine = int.from_bytes(data[e_lfanew + 4:e_lfanew + 6], 'little')
            if machine == 0x8664:
                print(f"Detected: 64-bit PE (x64/AMD64)", file=sys.stderr)
            elif machine == 0x014c:
                print(f"Detected: 32-bit PE (x86/i386)", file=sys.stderr)
            else:
                print(f"Detected: Unknown machine type (0x{machine:04x})", file=sys.stderr)

    # Build the C array output
    output_lines = []
    output_lines.append(f"// Auto-generated from: {os.path.basename(input_path)}")
    output_lines.append(f"// Size: {len(data)} bytes (0x{len(data):X})")
    output_lines.append(f"unsigned char {var_name}[{len(data)}] = {{")

    # Convert bytes to hex format
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_values = ", ".join(f"0x{b:02X}" for b in chunk)

        # Add trailing comma except for the last chunk
        if i + bytes_per_line < len(data):
            hex_values += ","

        output_lines.append(f"\t{hex_values}")

    output_lines.append("};")
    output_lines.append("")  # Final newline

    output_content = "\n".join(output_lines)

    # Write or print output
    if output_path:
        try:
            with open(output_path, "w") as f:
                f.write(output_content)
            print(f"Output written to: {output_path}", file=sys.stderr)
            print(f"Array size: {len(data)} bytes", file=sys.stderr)
        except IOError as e:
            print(f"Error writing output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_content)


def main():
    parser = argparse.ArgumentParser(
        description="Convert a binary file to a C-style unsigned char array",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s game.exe                    # Print to stdout
  %(prog)s game.exe game_data.h        # Write to file
  %(prog)s game.exe -n gamePayload     # Custom variable name
  %(prog)s game.exe out.h -b 12        # 12 bytes per line
        """
    )
    parser.add_argument("input", help="Input binary file path")
    parser.add_argument("output", nargs="?", help="Output file path (optional, prints to stdout)")
    parser.add_argument("-n", "--name", default="rawData",
                        help="Variable name for the array (default: rawData)")
    parser.add_argument("-b", "--bytes-per-line", type=int, default=16,
                        help="Bytes per line in output (default: 16)")

    args = parser.parse_args()

    convert_binary_to_carray(
        args.input,
        args.output,
        args.name,
        args.bytes_per_line
    )


if __name__ == "__main__":
    main()
