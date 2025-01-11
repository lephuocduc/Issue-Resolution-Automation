# Automation Project

This project aims to automate the resolution of tickets in ServiceNow. The primary objective is to develop scripts that can resolve issues automatically when executed from a jump host. If the scripts cannot fully resolve the issues, they will at least reduce the effort required by engineers to log in or check server information.

## Project Structure

- **AutomationProject.exe**: The main executable for the project.
- **bin/**: Contains various build outputs and configurations.
- **challenges.txt**: Lists challenges and tasks related to the project.
- **config.txt**: Configuration file for setting up the environment.
- **git.ps1**: PowerShell script for Git operations.
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
2. **Configuration**: Update `config.txt` with the appropriate paths and settings.
3. **Execution**: Run `UI.ps1` to launch the user interface and execute scripts as needed.

## Usage

- **LowFreeSpace.ps1**: Use this script to handle low disk space issues on servers. It can be executed from the UI or directly from the command line.
- **module.ps1**: Contains core functions such as `Write-Message`, `Test-ServerAvailability`, and `Get-Session`.
- **UnitTests**: Run the tests in `UnitTests/module.Tests.ps1` to ensure the scripts are functioning correctly.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Create a new Pull Request.

## License

This project is licensed under the MIT License.