import PyInstaller.__main__
import os
import shutil
import sys

def build_executable():
    """Build the standalone executable"""
    
    print("=== Building Network Flow Monitor ===\n")
    
    # Clean previous builds
    for folder in ['build', 'dist']:
        if os.path.exists(folder):
            shutil.rmtree(folder)
            print(f"Cleaned: {folder}")
    
    # List of files to include
    additional_files = [
        ('pcap2csv_win_v2.exe', '.'),
        ('README.txt', '.'),
    ]
    
    # Prepare add-data arguments
    datas_args = []
    for src, dst in additional_files:
        if os.path.exists(src):
            datas_args.append(f'--add-data={src}{os.pathsep}{dst}')
            print(f"Including: {src}")
        else:
            print(f"Warning: {src} not found!")
    
    # Hidden imports (packages PyInstaller might miss)
    # Add these to hidden_imports:
    hidden_imports = [
        'scapy',
        'scapy.layers',
        'scapy.layers.http',
        'scapy.layers.tls',
        'scapy.layers.tls.handshake',
        'scapy.sendrecv',
        'scapy.utils',
        'psutil',
        'requests',           # Already here
        'urllib3',
        'chardet',
        'idna',
        'numpy',
        'tkinter',
        'json',              # Add this
        'hashlib',           # Add this
        'datetime',          # Add this
    ]
    
    hidden_args = []
    for imp in hidden_imports:
        hidden_args.append(f'--hidden-import={imp}')
    
    # Build command
    args = [
        'network_monitor.py',           # Main script
        '--name=NetworkFlowMonitor',    # Output name
        '--onefile',                    # Single executable
        '--console',                    # Show console
        '--clean',                      # Clean build
        '--noconfirm',                  # Don't ask for confirmation
        '--upx-exclude=vcruntime140.dll',  # Exclude from compression
    ]
    
    # Add data files
    args.extend(datas_args)
    
    # Add hidden imports
    args.extend(hidden_args)
    
    # Optional: Add icon if exists
    if os.path.exists('icon.ico'):
        args.append('--icon=icon.ico')
        print("Including icon")
    
    print("\nBuilding executable (this may take a few minutes)...")
    
    # Run PyInstaller
    PyInstaller.__main__.run(args)
    
    print("\n" + "=" * 50)
    print("BUILD COMPLETE!")
    print("=" * 50)
    print(f"\nExecutable created in: dist/NetworkFlowMonitor.exe")
    print(f"Size: {os.path.getsize('dist/NetworkFlowMonitor.exe') / (1024*1024):.1f} MB")
    
    print("\n" + "=" * 50)
    print("DEPLOYMENT INSTRUCTIONS:")
    print("=" * 50)
    print("1. Copy NetworkFlowMonitor.exe to any Windows machine")
    print("2. Double-click to run")
    print("3. It will automatically:")
    print("   - Find network interfaces")
    print("   - Capture traffic")
    print("   - Extract flows and URLs")
    print("   - Send to your server")
    print("   - Store offline if server unavailable")

if __name__ == "__main__":
    # Check if we have the required files
    required_files = ['network_monitor.py', 'pcap2csv_win_v2.exe']
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("ERROR: Missing required files:")
        for file in missing_files:
            print(f"  - {file}")
        print(f"\nPlace all files in: {os.getcwd()}")
        sys.exit(1)
    
    # Build the executable
    build_executable()