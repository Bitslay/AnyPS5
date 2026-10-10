"""
FSELF to ELF Unpacker for PS5 Homebrew
Converts Fake-Signed ELF (FSELF, magic 0x1d3d154f) containers into raw unencrypted ELF binaries
ready for relinker.exe.
"""
import sys
import struct
from pathlib import Path

def unpack_fself(input_path, output_path=None):
    input_path = Path(input_path)
    if output_path is None:
        output_path = input_path.with_suffix('.elf') if input_path.suffix != '.elf' else input_path.with_name(input_path.stem + '_unself.elf')
    else:
        output_path = Path(output_path)

    data = input_path.read_bytes()
    if len(data) < 416 + 64:
        raise ValueError(f"{input_path}: File too small to be a valid SELF container")

    magic = struct.unpack('<I', data[:4])[0]
    if magic != 0x1d3d154f:
        if data[:4] == b'\x7fELF':
            print(f"{input_path} is already a raw ELF binary!")
            if input_path != output_path:
                output_path.write_bytes(data)
            return output_path
        raise ValueError(f"{input_path}: Unsupported or commercial encrypted SELF magic (0x{magic:08x}). Only unencrypted homebrew FSELF (0x1d3d154f) is supported.")

    elf_hdr = data[416:416+64]
    e_phoff = struct.unpack('<Q', elf_hdr[32:40])[0]
    e_phentsize, e_phnum = struct.unpack('<HH', elf_hdr[54:58])

    phs = []
    max_size = 0
    for i in range(e_phnum):
        ph_raw = data[416 + e_phoff + i * e_phentsize : 416 + e_phoff + (i+1) * e_phentsize]
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('<IIQQQQQQ', ph_raw)
        phs.append((p_type, p_offset, p_filesz))
        if p_offset + p_filesz > max_size:
            max_size = p_offset + p_filesz

    elf_buf = bytearray(max_size)

    hdr_size = e_phoff + e_phnum * e_phentsize
    elf_buf[0:hdr_size] = data[416:416+hdr_size]

    num_entries = struct.unpack('<H', data[24:26])[0]
    for i in range(num_entries):
        entry_raw = data[32 + i * 32 : 32 + (i+1) * 32]
        props, offset, filesz, memsz = struct.unpack('<QQQQ', entry_raw)
        seg_idx = (props >> 20) & 0xFFF
        is_segment = (props & 0x2000) != 0 or (props & 0x800) != 0
        if is_segment and seg_idx < len(phs):
            p_type, p_offset, p_filesz = phs[seg_idx]
            elf_buf[p_offset : p_offset + filesz] = data[offset : offset + filesz]

    output_path.write_bytes(elf_buf)
    print(f"Successfully extracted {output_path} ({len(elf_buf)} bytes)")
    return output_path

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python unself_fself.py <input.bin> [output.elf]")
        sys.exit(1)
    unpack_fself(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
