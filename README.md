# Automation For Issue Resolutions Project

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
* ScriptManager.ps1: Main GUI application built with Windows Forms
* module.ps1: Core utility functions for remote server operations
* Scripts/*.ps1: Individual automation scripts for specific tasks
* package.psd1: Build configuration for compiling to executable

### Key Features
* Windows Forms-based GUI interface
* Dynamic script loading and execution
* Remote server connectivity and authentication
* Detailed logging and reporting
* Error handling and retry logic

### Workflow
1. Developer writes PowerShell scripts in the Scripts folder
2. Scripts are automatically integrated into the GUI via Watch-ScriptsFolder.ps1
3. Changes trigger GitHub Actions CI/CD pipeline
4. Compiled executable is generated and published

## Testing
### Unit Tests
* Located in module.Tests.ps1
* Tests core functionality like:
    + Server connectivity
    + Session management
    + Error handling

### CI/CD Pipeline
* Automated testing via GitHub Actions
* Unit tests must pass before build
* Configured in workflow.yml

## From Developer
### Script Integration
1. Create new script in Scripts directory
2. Script is automatically added to GUI dropdown
3. Functions should use utilities from module.ps1
4. Add error handling and logging

### Building the Application
1. Update version in package.psd1
2. Push changes to trigger GitHub Actions
3. Pipeline will:
    * Run tests
    * Build executable
    * Publish new release

## From User
### Installation Guide
1. Prerequisites:
    * Windows PowerShell 5.1+
    * .NET Framework 4.6.2
    * Administrative access to target servers
2. Setup:
    * Download latest ScriptManager.exe release
    * Place in desired location
    * No installation required

### Usage
1. Launch ScriptManager.exe
2. Select script from dropdown menu
3. Enter required parameters
4. Click OK to execute
5. Review generated reports in C:\temp

The application provides:
* Simple GUI interface
* Clear error messages
* Detailed execution logs
* Status updates during long operations
* For script-specific instructions, refer to the comments in each script file under the Scripts directory.