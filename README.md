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
```
###########

# Automation For Issue Resolutions Project Documentation

## Introduction
This project implements an automation tool for IT support engineers to resolve common system issues. It provides a centralized GUI interface for executing maintenance scripts that help diagnose and fix problems on remote servers.

## Project Goal
The primary objective is to streamline the resolution of ServiceNow tickets by:

* Providing an easy-to-use GUI interface for script execution
* Automating common maintenance tasks like disk cleanup
* Reducing manual effort required by support engineers
* Generating detailed reports for documentation

## Technical Architecture
### Core Components
ScriptManager.ps1: Main GUI application built with Windows Forms
module.ps1: Core utility functions for remote server operations
Scripts/*.ps1: Individual automation scripts for specific tasks
package.psd1: Build configuration for compiling to executable
Key Features
Windows Forms-based GUI interface
Dynamic script loading and execution
Remote server connectivity and authentication
Detailed logging and reporting
Error handling and retry logic
Workflow
Developer writes PowerShell scripts in the Scripts folder
Scripts are automatically integrated into the GUI via Watch-ScriptsFolder.ps1
Changes trigger GitHub Actions CI/CD pipeline
Compiled executable is generated and published
Testing
Unit Tests
Located in module.Tests.ps1
Tests core functionality like:
Server connectivity
Session management
Error handling
CI/CD Pipeline
Automated testing via GitHub Actions
Unit tests must pass before build
Configured in workflow.yml
From Developer
Script Integration
Create new script in Scripts directory
Script is automatically added to GUI dropdown
Functions should use utilities from module.ps1
Add error handling and logging
Building the Application
Update version in package.psd1
Push changes to trigger GitHub Actions
Pipeline will:
Run tests
Build executable
Publish new release
From User
Installation Guide
Prerequisites:

Windows PowerShell 5.1+
.NET Framework 4.6.2
Administrative access to target servers
Setup:

Download latest ScriptManager.exe release
Place in desired location
No installation required
Usage
Launch ScriptManager.exe
Select script from dropdown menu
Enter required parameters
Click OK to execute
Review generated reports in C:\temp
The application provides:

Simple GUI interface
Clear error messages
Detailed execution logs
Status updates during long operations
For script-specific instructions, refer to the comments in each script file under the Scripts directory.