# build.ps1

# Define paths
$sourcePath = Join-Path $PSScriptRoot 'Scripts'
$destinationPath = Join-Path $PSScriptRoot 'output\Scripts'

# Create destination directory if it doesn't exist
if (-not (Test-Path $destinationPath)) {
    New-Item -ItemType Directory -Path $destinationPath
}

# Copy Scripts folder to output directory
Copy-Item -Path $sourcePath\* -Destination $destinationPath -Recurse -Force

# Additional build steps can be included here
