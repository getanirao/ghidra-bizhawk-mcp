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
# Native stderr must not become terminating errors under $ErrorActionPreference = 'Stop'
$ErrorActionPreference = 'Continue'
$pipOut = pip install --target "$LibDir" --no-compile -e "$RepoRoot" --quiet 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "pip install failed with exit code $LASTEXITCODE`n$pipOut"
}
$ErrorActionPreference = 'Stop'
# Remove dev/optional baggage
Get-ChildItem -Recurse $LibDir -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse $LibDir -Filter "*.pyc" | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem -Recurse $LibDir -Directory -Filter "*.dist-info" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Dependencies installed" -ForegroundColor Green

# Try mcpb CLI first, fall back to manual ZIP
$McpbPath = (Get-Command "mcpb" -ErrorAction SilentlyContinue)
$OutBundle = Join-Path $RepoRoot "dist/ghidra-bizhawk-mcp.mcpb"
if ($McpbPath) {
    Push-Location $BundleDir
    try {
        $ErrorActionPreference = 'Continue'
        $packOut = mcpb pack . "$OutBundle" 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "mcpb pack failed with exit code $LASTEXITCODE`n$packOut"
        }
        $ErrorActionPreference = 'Stop'
        Write-Host "mcpb pack complete" -ForegroundColor Green
    } finally {
        Pop-Location
    }
} else {
    Write-Host "mcpb CLI not found. Creating manual ZIP bundle..." -ForegroundColor Yellow
    Write-Host "Install with: npm install -g @anthropic-ai/mcpb" -ForegroundColor Yellow
    Compress-Archive -Path "$BundleDir/*" -DestinationPath $OutBundle -Force
}

# Build the Smithery publish variant (manifest patched with MCP tool schemas,
# which the MCPB schema forbids but Smithery's publish API requires)
$ErrorActionPreference = 'Continue'
$variantOut = python (Join-Path $RepoRoot "scripts/build_smithery_bundle.py") 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
    throw "build_smithery_bundle.py failed with exit code $LASTEXITCODE`n$variantOut"
}
$ErrorActionPreference = 'Stop'
Write-Host "Smithery bundle variant created" -ForegroundColor Green

# Cleanup
Remove-Item -Recurse -Force $BundleDir

Write-Host "Bundle created: $RepoRoot/dist/ghidra-bizhawk-mcp.mcpb" -ForegroundColor Green
