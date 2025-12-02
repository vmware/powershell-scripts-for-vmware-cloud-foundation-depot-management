# PowerShell Scripts for VMware Cloud Foundation Depot Management

[![License](https://img.shields.io/badge/License-Broadcom-green.svg)](LICENSE.md)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-blue.svg)](https://github.com/PowerShell/PowerShell)

A collection of PowerShell scripts to help manage and configure VMware depot repositories for VMware Cloud Foundation (VCF) and vCenter Server environments.

## 📋 Overview

This repository contains utilities for managing the transition to VMware by Broadcom's new depot structure with unique URIs. These tools help administrators update repository configurations across vCenter and SDDC Manager deployments.

## 🛠️ Available Scripts

### VMwareDepotChange

Reconfigure customer repositories for SDDC Manager and vCenter to use the new VMware by Broadcom depot structures.

**Location:** [VMwareDepotChange](https://github.com/vmware/powershell-scripts-for-vmware-cloud-foundation-depot-management/tree/main/VMwareDepotChange)

**Key Features:**
- Support for standalone vCenter servers
- Support for VMware Cloud Foundation (VCF) SDDC Manager deployments
- Check current depot configurations
- Update to new depot URLs with Broadcom download tokens
- Restore original depot configurations
- Interactive menu mode for ease of use

**Documentation:** See [VMwareDepotChange/README.md](VMwareDepotChange/README.md) for detailed usage instructions.

**Quick Start:**
```bash
cd VMwareDepotChange
./VMwareDepotChange.ps1 -Connect -Endpoint vCenter -JsonInput samples/sample-vcenters.json
./VMwareDepotChange.ps1 -Check
./VMwareDepotChange.ps1 -Update -DownloadToken <YourBroadcomDownloadToken>
```

## 📚 Prerequisites

- PowerShell 7.x or later
- VCF.PowerCLI module
- Administrative credentials for vCenter or SDDC Manager
- Broadcom download token (for depot updates)

## 🔗 Additional Resources

- [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [PowerCLI Installation Guide](https://developer.broadcom.com/powercli/installation-guide)
- [VMware by Broadcom Support Portal](https://support.broadcom.com/)
- [Knowledge Base Article 389276](https://knowledge.broadcom.com/external/article/389276)

## 📄 License

See [LICENSE.md](LICENSE.md) for license information.

---

**Copyright © 2025 Broadcom. All Rights Reserved.**

