# VMware Depot Change Script

Reconfigure customer repositories for SDDC Manager and vCenter to use the new VMware by Broadcom depot structures with unique URIs.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
  - [vCenter Endpoint Configuration](#vcenter-endpoint-configuration)
  - [VCF Endpoint Configuration](#vcf-endpoint-configuration)
- [Usage](#usage)
  - [Connection](#connection)
  - [Depot Operations](#depot-operations)
  - [Advanced Options](#advanced-options)
- [Log Levels](#log-levels)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)
- [Additional Resources](#additional-resources)

## Overview

This script helps users transition to the new VMware by Broadcom depot structures. It supports both standalone vCenter servers and VMware Cloud Foundation (VCF) SDDC Manager deployments.

**Knowledge Base Article:** [KB 389276](https://knowledge.broadcom.com/external/article/389276)

## Features

### ✨ Key Capabilities
- ✅ **Dual Mode Operation**: Interactive menu or headless automation
- ✅ **Multi-Target Support**: Update multiple vCenter servers simultaneously
- ✅ **VCF Integration**: Automatic vCenter discovery and credential management
- ✅ **Comprehensive Logging**: 6-level hierarchical logging (DEBUG → INFO → ADVISORY → WARNING → EXCEPTION → ERROR)
- ✅ **Dry Run Mode**: Validate changes before applying
- ✅ **WhatIf Support**: Preview operations without execution
- ✅ **Robust Error Handling**: Detailed error messages with troubleshooting guidance
- ✅ **Strict Mode**: Enhanced error detection and validation
- ✅ **Parameter Validation**: Automatic validation of download token format
- ✅ **Progress Indicators**: Visual feedback during long-running operations
- ✅ **Standardized Exit Codes**: Automation-friendly exit status

### 🎯 What Gets Updated
1. **vCenter ESXi Host Depots**
   - Partner provided addons
   - vSphere ESXi and ESX patches
   - VMware Certified Async Drivers
   - VMware Async Releases for VM-tools

2. **vCenter Appliance Update Depot**
   - Custom depot URLs with download token
   - Version-specific manifest paths

3. **SDDC Manager Depots** (VCF 5.2 and earlier)
   - LCM manifest directories
   - Product version catalogs
   - Repository configurations

## Prerequisites

- **PowerShell 7.2 or later** (required)
- **VCF.PowerCLI module** (latest version recommended)
- **Administrative credentials** for vCenter or SDDC Manager
  - vCenter: Administrator role required
  - SDDC Manager: ADMIN role required (for credential retrieval)
- **Broadcom download token** (32 alphanumeric characters) for depot updates
- **Network connectivity** to target systems from script execution host

## Installation

1. **Install PowerShell** (macOS/Linux/Windows)
   ```bash
   # Follow the installation guide at:
   # https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell
   ```

2. **Install PowerCLI**
   ```powershell
   Install-Module -Name VMware.PowerCLI -Scope CurrentUser
   # Or visit: https://developer.broadcom.com/powercli/installation-guide
   ```

3. **Configure PowerCLI** (recommended for internal use)
   ```powershell
   # Disable certificate validation (for internal/test environments)
   Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

   # Enable multiple vCenter connections
   Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Confirm:$false
   ```

## Configuration

Create a JSON configuration file to define your endpoints. Sample files are provided in the `samples/` directory:
- `samples/sample-vcenters.json` - vCenter with credentials
- `samples/sample-vcenters-nocredentials.json` - vCenter without credentials (will prompt)
- `samples/sample-vcf.json` - VCF with credentials
- `samples/sample-vcf-nocredentials.json` - VCF without credentials (will prompt)

### vCenter Endpoint Configuration

Create a JSON file with one or more vCenter servers:

```json
[
  {
    "VcenterFqdn": "vcenter01.example.com",
    "VcenterUsername": "administrator@vsphere.local",
    "VcenterPassword": "Password1!"
  },
  {
    "VcenterFqdn": "vcenter02.example.com",
    "VcenterUsername": "administrator@vsphere.local",
    "VcenterPassword": "Password1!"
  }
]
```

> **Note:** `VcenterUsername` and `VcenterPassword` are optional. If omitted, you will be prompted for credentials.

### VCF Endpoint Configuration

Create a JSON file for SDDC Manager:

```json
[
  {
    "SddcManagerFqdn": "vcf01.example.com",
    "SddcManagerUserName": "administrator@vsphere.local",
    "SddcManagerPassword": "Password1!",
    "SddcManagerRootPassword": "Password1!Password1!"
  }
]
```

> **Note:** `SddcManagerUserName`, `SddcManagerPassword`, and `SddcManagerRootPassword` are optional. If omitted, you will be prompted for credentials.

## Usage

### Connection

Connect to your endpoint using the JSON configuration file:

**Connect to vCenter:**
```bash
./VMwareDepotChange.ps1 -Connect -Endpoint vCenter -JsonInput /path/to/vcenters.json
```

**Connect to VCF SDDC Manager:**
```bash
./VMwareDepotChange.ps1 -Connect -Endpoint Vcf -JsonInput /path/to/vcf.json
```

### Depot Operations

Once connected, you can perform the following operations:

**Check Current Depot Configuration:**
```bash
./VMwareDepotChange.ps1 -Check
```

**Update Depot to New URLs:**
```bash
./VMwareDepotChange.ps1 -Update -DownloadToken <YourBroadcomDownloadToken>
```

**Restore Original Depot Configuration:**
```bash
./VMwareDepotChange.ps1 -Restore
```

**Disconnect from Endpoints:**
```bash
./VMwareDepotChange.ps1 -Disconnect
```

### Advanced Options

**Interactive Menu Mode:**
```bash
./VMwareDepotChange.ps1
```
Launches an interactive menu to guide you through available operations.

**Display Script Version:**
```bash
./VMwareDepotChange.ps1 -Version
```

**Display Help:**
```bash
./VMwareDepotChange.ps1 -Help
```

**Dry Run Mode:**
```bash
./VMwareDepotChange.ps1 -DryRun -DownloadToken <Token>
```
Validates the download token and depot URLs without making any changes.

**Debug/Verbose Logging:**
```bash
# Enable debug logging for troubleshooting
./VMwareDepotChange.ps1 -Check -LogLevel DEBUG

# Use PowerShell verbose output
./VMwareDepotChange.ps1 -Check -Verbose

# Use PowerShell debug output
./VMwareDepotChange.ps1 -Check -Debug
```

**WhatIf Mode (Preview Changes):**
```bash
./VMwareDepotChange.ps1 -Update -DownloadToken <Token> -WhatIf
```
Shows what changes would be made without actually applying them.

**Confirm Before Changes:**
```bash
./VMwareDepotChange.ps1 -Update -DownloadToken <Token> -Confirm
```
Prompts for confirmation before making changes.

**Silent Mode:**
```bash
./VMwareDepotChange.ps1 -Check -Silence
```
Suppresses console output (logs still written to file).

**Skip SDDC Manager Task Check:**
```bash
./VMwareDepotChange.ps1 -Update -DownloadToken <Token> -SkipSddcManagerTaskCheck
```

## Additional Resources

- [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [PowerCLI Installation Guide](https://developer.broadcom.com/powercli/installation-guide)
- [VMware by Broadcom Support Portal](https://support.broadcom.com/)
- [Knowledge Base Article 389276](https://knowledge.broadcom.com/external/article/389276)

---

**Copyright © 2025 Broadcom. All Rights Reserved.**
