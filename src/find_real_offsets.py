#!/usr/bin/env python3
"""
find_real_offsets.py
Extract real EPROCESS offsets from your Volatility3 symbols
This will give us the correct offsets for your specific Windows 7 build
"""

import json
import lzma
import sys
import os

def find_eprocess_offsets(symbols_file):
    """Extract EPROCESS structure offsets from Volatility3 symbols"""
    
    print("================================================================================")
    print("EXTRACTING REAL EPROCESS OFFSETS FROM VOLATILITY3 SYMBOLS")
    print("================================================================================")
    
    try:
        # Read the compressed JSON symbols file
        print(f"[+] Reading symbols from: {symbols_file}")
        with lzma.open(symbols_file, 'rt') as f:
            symbols = json.load(f)
        
        print("[+] Symbols loaded successfully")
        
        # Find EPROCESS structure
        user_types = symbols.get('user_types', {})
        eprocess = None
        
        for type_name, type_info in user_types.items():
            if 'EPROCESS' in type_name and type_info.get('kind') == 'struct':
                eprocess = type_info
                print(f"[+] Found EPROCESS structure: {type_name}")
                break
        
        if not eprocess:
            print("[-] EPROCESS structure not found in symbols")
            return None
        
        # Extract the fields we need
        fields = eprocess.get('fields', {})
        offsets = {}
        
        # Key fields for VMI
        key_fields = {
            'ActiveProcessLinks': 'win_tasks',
            'UniqueProcessId': 'win_pid', 
            'ImageFileName': 'win_pname',
            'Peb': 'win_peb',
            'ThreadListHead': 'win_threads',
            'DirectoryTableBase': 'win_pdbase'
        }
        
        print("\nEPROCESS Field Offsets:")
        print("Field Name           Offset    LibVMI Config")
        print("----------------     ------    -------------")
        
        for field_name, config_name in key_fields.items():
            if field_name in fields:
                offset = fields[field_name]['offset']
                offsets[config_name] = offset
                print(f"{field_name:<16} 0x{offset:03x}     {config_name} = 0x{offset:x};")
            else:
                print(f"{field_name:<16} NOT FOUND")
        
        return offsets
        
    except Exception as e:
        print(f"[-] Error reading symbols: {e}")
        return None

def generate_libvmi_config(offsets):
    """Generate the correct libvmi.conf with real offsets"""
    
    if not offsets:
        print("[-] No offsets found, cannot generate config")
        return
    
    print("\n" + "="*80)
    print("CORRECT LIBVMI.CONF FOR YOUR WINDOWS 7 BUILD")
    print("="*80)
    
    config = """# CORRECT LibVMI Configuration for Your Windows 7 Build
# Generated from real Volatility3 symbols
# PDB GUID: 3844dbb920174967be7aa4a2c20430fa2

win7-vmi {
    ostype = "Windows";
    
    # Real EPROCESS offsets from your kernel symbols"""
    
    for config_name, offset in offsets.items():
        config += f"\n    {config_name} = 0x{offset:x};"
    
    config += """
    
    # Optional: Kernel information from vmi-win-guid
    win_kdbg = 0x1f10a0;
    win_kdvb = 0xfffff8000284e0a0;
    win_ntoskrnl = 0x265d000;
}"""
    
    print(config)
    
    # Save to file
    with open('libvmi_real_offsets.conf', 'w') as f:
        f.write(config)
    
    print(f"\n[+] Configuration saved to: libvmi_real_offsets.conf")
    print("[+] Copy this to /etc/libvmi.conf to fix the garbled names")

def main():
    # Path to your volatility3 symbols
    symbols_path = "~/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz"
    symbols_path = os.path.expanduser(symbols_path)
    
    if not os.path.exists(symbols_path):
        print("[-] Symbols file not found at expected location")
        print(f"    Expected: {symbols_path}")
        print("\nPlease provide the correct path to your symbols file:")
        print("    python3 find_real_offsets.py /path/to/symbols.json.xz")
        return
    
    # Extract real offsets
    offsets = find_eprocess_offsets(symbols_path)
    
    if offsets:
        generate_libvmi_config(offsets)
        print("\n" + "="*80)
        print("NEXT STEPS:")
        print("1. sudo cp libvmi_real_offsets.conf /etc/libvmi.conf")
        print("2. sudo vmi-process-list win7-vmi")
        print("3. Verify process names are readable (no more garbled text)")
        print("="*80)
    else:
        print("[-] Failed to extract offsets")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        symbols_file = sys.argv[1]
        offsets = find_eprocess_offsets(symbols_file)
        if offsets:
            generate_libvmi_config(offsets)
    else:
        main()