# Virtual machine introspection and hypervisor test Documentation



## Project Overview
This project demonstrates the capabilities of Virtual Machine Introspection using KVM hypervisor and the LibVMI framework. The implementation provides live analysis of Windows guest virtual machines from the hypervisor layer without requiring guest-side agents.

### Objectives
- Deploy KVM-VMI infrastructure with LibVMI integration
- Implement C program for live VM introspection
- Demonstrate process, module, and thread enumeration
- Prove hypervisor-level security monitoring capabilities
## Technical Architecture
### Environment Specifications
- **Host OS**: Ubuntu Linux (KVM/QEMU hypervisor)
- **Guest OS**: Windows 7 SP1 x64
- **VMI Framework**: LibVMI with KVM integration
- **Programming**: C language with LibVMI API
- **Infrastructure**: Dedicated server environment
### Component Architecture
```
// Define groups and nodes
Developer [icon: user]
VMI Results [icon: monitor]

Host Ubuntu Server [icon: linux] {
  VMI Applications [color: blue] {
    LibVMI Framework [icon: library]
    VMI Demo App [icon: code]
    Configuration [icon: settings]
  }
  
  Hypervisor Layer [color: green] {
    KVM Engine [icon: server]
    QEMU Manager [icon: virtual-machine]
    Memory Manager [icon: memory]
  }
}

Guest VMs [color: red] {
  Windows 7 VM [icon: windows]
  VM Memory [icon: database]
  VM Processes [icon: process]
}

Security Analysis [icon: shield] {
  Process Monitor [icon: list]
  Memory Inspector [icon: search]
  Thread Analyzer [icon: network]
}

// Define connections
Developer > VMI Demo App
VMI Demo App > LibVMI Framework
LibVMI Framework > Configuration
LibVMI Framework > KVM Engine
KVM Engine > QEMU Manager
QEMU Manager > Windows 7 VM
Windows 7 VM > VM Memory, VM Processes
LibVMI Framework > Memory Manager
Memory Manager > VM Memory
VMI Demo App > Security Analysis
Security Analysis > Process Monitor, Memory Inspector, Thread Analyzer
Security Analysis > VMI Results
```
## Installation and Setup
### Prerequisites
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install virtualization packages
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils

# Install development tools
sudo apt install build-essential cmake git

# Install LibVMI dependencies
sudo apt install libglib2.0-dev libjson-c-dev libyajl-dev
```
### LibVMI Installation
```bash
# Clone LibVMI repository
git clone https://github.com/libvmi/libvmi.git
cd libvmi

# Build and install
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make
sudo make install
sudo ldconfig
```
### Windows 7 VM Setup
```bash
# Create VM disk
qemu-img create -f qcow2 win7-vmi.qcow2 40G

# Install Windows 7 (replace with your ISO path)
sudo virt-install \
  --name win7-vmi \
  --ram 16384 \
  --vcpus 8 \
  --disk path=/var/lib/libvirt/images/win7-vmi.qcow2,size=80,format=qcow2 \
  --cdrom ISOs/windows7.iso \
  --network network=default \
  --graphics vnc,listen=0.0.0.0 \
  --os-variant win7 \
  --boot hd,cdrom \
  --noautoconsole
```
## Configuration
### LibVMI Configuration (/etc/libvmi.conf)
```ini
win7-vmi {
    ostype = "Windows";
    win_pdbase = 0x28;
    win_pid = 0x180;
    win_tasks = 0x188;
    win_pname = 0x2e0;
    win_ntoskrnl = 0x265d000;
}
```
### Verification Commands
```bash
# Check VM status
virsh list --all

# Test LibVMI functionality
sudo vmi-process-list win7-vmi

# Verify kernel symbol resolution
sudo vmi-dump-memory win7-vmi | head -10
```
## Implementation Details
### Core Components
#### 1. VMI Initialization
```c
static demo_error_t initialize_vmi(const char *domain_name) {
    if (VMI_FAILURE == vmi_init_complete(&g_vmi, domain_name, VMI_INIT_DOMAINNAME, 
                                        NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL)) {
        return DEMO_ERROR_INIT;
    }
    return DEMO_SUCCESS;
}
```
#### 2. Process Enumeration
- Locates `PsActiveProcessHead`  kernel symbol
- Traverses `win_tasks`  linked list
- Extracts PID, process name, and EPROCESS addresses
- **Result**: 38 active processes identified
#### 3. Memory Analysis
- Demonstrates cross-process memory access
- Reads EPROCESS structure fields
- Validates memory translation capabilities
- **Result**: Successful memory space analysis for 10+ processes
#### 4. Thread Analysis
- Identifies thread-related structures within processes
- Analyzes kernel address space pointers
- Demonstrates hypervisor-level thread visibility
- **Result**: Thread structures identified across multiple processes
### Key Functions
```c
// Main introspection functions
static demo_error_t enumerate_processes(void);
static demo_error_t enumerate_modules(void);
static demo_error_t enumerate_threads(void);

// Helper utilities
static size_t get_offset_safe(const char *offset_name);
static void cleanup_vmi(void);
```
## Usage Instructions
### Building the Application
```bash
# Navigate to source directory
cd ~/VMI-Project/src

# Clean and build
make clean
make

# Verify compilation
ls -la stealthium_vmi_demo
```
### Running the Demo
```bash
# Ensure VM is running
virsh start win7-vmi

# Run VMI demonstration
sudo ./stealthium_vmi_demo win7-vmi

# Optional: Run with custom domain name
sudo ./stealthium_vmi_demo <domain-name>
```
### Expected Output Format
```
================================================================================
        STEALTHIUM VMI DEMONSTRATION
    Virtual Machine Introspection Demo - Compatible Version
================================================================================
Target VM: win7-vmi
Timestamp: Sat May 24 13:08:46 2025

============================================================
PROCESS ENUMERATION
============================================================
[    4] System               (EPROCESS: 0xfffffa800d984040)
[  228] smss.exe             (EPROCESS: 0xfffffa800ec8f440)
[  316] csrss.exe            (EPROCESS: 0xfffffa800ea8b500)
...

Total processes found: 38
```
## Results and Capabilities Demonstrated
### Process Introspection Results
- **Total Processes Detected**: 38+ active Windows processes
- **System Processes**: System (PID 4), smss.exe (PID 228), csrss.exe (PID 316/360)
- **Service Processes**: services.exe (PID 400), lsass.exe (PID 412), multiple svchost.exe instances
- **User Applications**: explorer.exe (PID 836), iexplore.exe instances, mmc.exe, etc.
- **Memory Addresses**: Complete EPROCESS structure addresses extracted
- **Data Integrity**: 100% accurate PID and process name extraction
### LibVMI Performance Optimization
LibVMI provided optimization suggestions during execution:

```
LibVMI Suggestion: set win_kdbg=0x1f10a0 in libvmi.conf for faster startup
LibVMI Suggestion: set win_kdvb=0xfffff8000284e0a0 in libvmi.conf for faster startup
```
### Screenshot Evidence
The implementation includes visual evidence showing:

1. **Development Environment**: VS Code with C source code and successful compilation
2. **VMI Execution**: Live process enumeration with complete output
3. **LibVMI Validation**: Native vmi-process-list tool confirming same results
4. **Configuration**: Working libvmi.conf with Windows 7 kernel offsets
### Technical Validation
- **Consistency Check**: Custom VMI program results match native `vmi-process-list`  output
- **Memory Access**: Successful EPROCESS structure reading at kernel level
- **Cross-Platform**: LibVMI integration working properly with KVM hypervisor
- **Real-time Operation**: Live introspection without guest VM interruption
- **Error Handling**: Graceful handling of missing kernel symbols with fallback analysis
### Performance Metrics
- **Hardware Utilization**: 16GB RAM, 4 CPU cores - optimal for VMI operations
- **Guest VM Stability**: Windows 7 SP1 x64 running stable under continuous introspection
- **Response Time**: Near real-time process enumeration and memory analysis
- **Accuracy**: 100% process detection rate compared to native LibVMI tools
## Project Verification
### Evidence Documentation
The project includes comprehensive visual evidence:

1. **Source Code**: Complete C implementation with professional error handling
2. **Build Process**: Successful compilation using standard Makefile
3. **Execution Results**: Live VMI demonstration with full process enumeration
4. **Native Tool Verification**: Confirmation using LibVMI's built-in utilities
5. **Configuration**: Working kernel offset configuration for Windows 7
## Troubleshooting Guide
### Common Issues
#### LibVMI Initialization Fails
```bash
# Check VM status
virsh list --all

# Verify LibVMI installation
sudo ldconfig
vmi-process-list --help

# Check configuration
sudo cat /etc/libvmi.conf
```
#### Kernel Symbol Errors
```bash
# Update kernel offsets
sudo vmi-win-guid win7-vmi

# Verify memory access
sudo vmi-dump-memory win7-vmi | head -5
```
#### Permission Issues
```bash
# Ensure proper privileges
sudo usermod -aG libvirt $USER
sudo usermod -aG kvm $USER

# Restart libvirt service
sudo systemctl restart libvirtd
```
### Performance Optimization
- Allocate sufficient memory to guest VM (minimum 2GB)
- Use SSD storage for VM disk images
- Enable hardware virtualization in BIOS
- Configure appropriate CPU allocation


## Project Structure
```
VMI-Project/                       #Removed ISO Directroy
├── src/
│   ├── vmi_stealthium_demo.c      # Main implementation
│   ├── Makefile                   # Build configuration
│   └── libvmi_fixed.conf          # LibVMI configuration
├── demo/                          # Demo recordings
├── img/                           # Screenshots and evidence
│   ├── processFixed    
│   ├── processlistSmashed.png 
│   ├── CurrentConfig.png      
│   └── process_enumeration.png    # Complete process listing
├── documentation/
│   └── README.md                  # via https://app.eraser.io/
└── README.md                      # Project overview
```
## Technical Specifications
### System Requirements
- **CPU**: 4 cores x64 with virtualization support (Intel VT-x or AMD-V)
- **Memory**: 16GB RAM (sufficient for host operations and guest VM)
- **Storage**: 80GB available space
- **OS**: Ubuntu 22.04+ or similar Linux distribution
### Actual Implementation Specifications
- **Host Memory**: 16GB RAM allocated
- **Host CPU**: 4 CPU cores assigned
- **Guest VM**: Windows 7 SP1 x64 (2GB RAM allocation)
- **Storage**: SSD storage for optimal VM performance
### Software Dependencies
- KVM/QEMU hypervisor
- LibVMI framework
- GCC compiler
- CMake build system
- libvirt management tools
## Conclusion
This VMI implementation successfully demonstrates hypervisor-level introspection capabilities essential for modern security platforms. The project proves the viability of agentless monitoring solutions and provides a foundation for runtime cloud protection systems.

The successful completion validates both the technical implementation and the practical applicability of VMI technology for security monitoring and threat detection applications.

---

**Author**: Mohamed Reda
 **Date**: 24 May 2025
 **Purpose**: Stealthium Technical Assessment
 **Status**: Complete and Functional

