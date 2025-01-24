# Automation For Issue Resolutions Project

![Workflow Diagram](Workflow/Workflow.png)


This project aims to automate the resolution of tickets in ServiceNow. The primary objective is to develop scripts that can resolve issues automatically when executed from a jump host. If the scripts cannot fully resolve the issues, at least they can reduce the effort required by engineers to log in or check server information.

## Prerequisites
- Windows PowerShell 5.1+
- .NET Framework 4.6.2
- Visual Studio 2019/2022
- Administrative access to target servers

## Quick Start
1. Clone the repository
2. Open `AutomationProject.sln` in Visual Studio
3. Build the solution
4. Run `ScriptManager.exe`

## Project Structure
AutomationProject/ ├── ScriptManager.ps1 # Main script with GUI ├── Scripts/ │ └── LowFreeSpace.ps1 # Disk space management ├── modules/ │ └── module.ps1 # Core functions └── UnitTests/ # Test suite


## Usage Examples
```powershell
# Launch GUI
.\ScriptManager.ps1

# Direct script execution
.\Scripts\LowFreeSpace.ps1

