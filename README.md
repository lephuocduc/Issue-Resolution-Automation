# Automation For Issue Resolutions Project

![Workflow Diagram](Workflow/Workflow.png)


This project aims to automate the resolution of tickets in ServiceNow. The primary objective is to develop scripts that can resolve issues automatically when executed from a jump host. If the scripts cannot fully resolve the issues, at least they can reduce the effort required by engineers to log in or check server information.

## Project Structure

- **ScriptManager.exe**: The main executable for the project.
- **modules/**: Contains PowerShell modules.
  - **module.ps1**: Core module with essential functions.
- **README.md**: This file.
- **Scripts/**: Contains various PowerShell scripts.
  - **LowFreeSpace.ps1**: Script to handle low disk space issues.
- **temp/**: Temporary scripts and files.
  - **cleanup1.ps1**: Script for cleaning up temporary files.
  - **cleanup2.ps1**: Additional cleanup script.
  - **temp.ps1**: Combined cleanup script.
- **UI.ps1**: PowerShell script providing a user interface for executing other scripts.
- **UnitTests/**: Contains unit tests for the project.

## Getting Started

1. **Setup**: Ensure you have PowerShell installed and configured to run scripts.
2. **Execution**: Run `ScriptManager.exe` to launch the user interface and execute scripts as needed.

## Usage 

- **LowFreeSpace.ps1**: Use this script to handle low disk space issues on servers. It can be executed from the UI or directly from the command line.
- **module.ps1**: Contains core functions such as `Write-Message`, `Test-ServerAvailability`, and `Get-Session`.
- **UnitTests**: Run the tests in `UnitTests/module.Tests.ps1` to ensure the scripts are functioning correctly.

