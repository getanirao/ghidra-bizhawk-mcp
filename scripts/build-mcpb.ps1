param(
    [string]$OutputDir = (Resolve-Path "dist")
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path "$PSScriptRoot/.."
$BundleDir = Join-Path $RepoRoot "dist/mcpb-bundle"

Write-Host "Building MCPB bundle for ghidra-bizhawk-mcp..." -ForegroundColor Cyan

# Create clean bundle directory
if (Test-Path $BundleDir) { Remove-Item -Recurse -Force $BundleDir }
New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null

# Copy required files
Copy-Item "$RepoRoot/mcpb/manifest.json" "$BundleDir/manifest.json"
Copy-Item "$RepoRoot/pyproject.toml" "$BundleDir/pyproject.toml"
Copy-Item "$RepoRoot/mcpb/.mcpbignore" "$BundleDir/.mcpbignore"

# Copy source tree
$SrcDest = "$BundleDir/src"
New-Item -ItemType Directory -Force -Path $SrcDest | Out-Null
Copy-Item -Recurse "$RepoRoot/src/ghidra_bizhawk_mcp" "$SrcDest/ghidra_bizhawk_mcp"

# Remove __pycache__ and .pyc
Get-ChildItem -Recurse $BundleDir -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -Recurse $BundleDir -Filter "*.pyc" | Remove-Item -Force

# Install runtime dependencies into server/lib/
Write-Host "Installing Python dependencies..." -ForegroundColor Cyan
$LibDir = Join-Path $BundleDir "server/lib"
New-Item -ItemType Directory -Force -Path $LibDir | Out-Null
pip install --target "$LibDir" --no-compile -e "$RepoRoot" --quiet 2>&1 | Out-Null
# Remove dev/optional baggage
Get-ChildItem -Recurse $LibDir -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse $LibDir -Filter "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse $LibDir -Directory -Filter "*.dist-info" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Dependencies installed" -ForegroundColor Green

# Try mcpb CLI first, fall back to manual ZIP
$McpbPath = (Get-Command "mcpb" -ErrorAction SilentlyContinue)
if ($McpbPath) {
    Push-Location $BundleDir
    try {
        mcpb pack
        Write-Host "mcpb pack complete" -ForegroundColor Green
        # Move .mcpb file to dist/
        Get-ChildItem "*.mcpb" | Move-Item -Destination "$RepoRoot/dist/" -Force
    } finally {
        Pop-Location
    }
} else {
    Write-Host "mcpb CLI not found. Creating manual ZIP bundle..." -ForegroundColor Yellow
    Write-Host "Install with: npm install -g @anthropic-ai/mcpb" -ForegroundColor Yellow
    Compress-Archive -Path "$BundleDir/*" -DestinationPath "$RepoRoot/dist/ghidra-bizhawk-mcp.mcpb" -Force
}

# Cleanup
Remove-Item -Recurse -Force $BundleDir

Write-Host "Bundle created: $RepoRoot/dist/ghidra-bizhawk-mcp.mcpb" -ForegroundColor Green
