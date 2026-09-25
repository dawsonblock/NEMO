# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

[CmdletBinding()]
param(
    [string]$InstallDir,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

$Repository = 'NVIDIA/NeMo-Relay'
$GitHubUrl = "https://github.com/$Repository"
$GitHubApiUrl = "https://api.github.com/repos/$Repository"

function Show-Usage {
    @'
Install the NeMo Relay CLI and its plugin host from GitHub Releases.

Both executables are installed into the same directory: the CLI starts the host
to run native plugins outside its own process, and looks for it beside itself.

Usage:
  irm https://raw.githubusercontent.com/NVIDIA/NeMo-Relay/main/install.ps1 | iex
  .\install.ps1 [-InstallDir DIR] [-Help]

Environment:
  NEMO_RELAY_VERSION   Release to install, for example 0.5.0 or v0.5.0.
                       Defaults to the latest stable release.

Options:
  -InstallDir DIR      Destination directory (default: %LOCALAPPDATA%\nemo-relay\bin).
  -Help                Show this help text.

Examples:
  irm https://raw.githubusercontent.com/NVIDIA/NeMo-Relay/main/install.ps1 | iex
  $env:NEMO_RELAY_VERSION = '0.5.0'; irm https://raw.githubusercontent.com/NVIDIA/NeMo-Relay/main/install.ps1 | iex
  .\install.ps1 -InstallDir "$HOME\bin"
'@ | Write-Output
}

function Fail([string]$Message) {
    throw "nemo-relay installer: $Message"
}

function Get-ReleaseVersion {
    $version = $env:NEMO_RELAY_VERSION
    if ([string]::IsNullOrWhiteSpace($version)) {
        Write-Host 'Finding the latest stable NeMo Relay release...'
        try {
            $headers = @{
                Accept = 'application/vnd.github+json'
                'User-Agent' = 'nemo-relay-install-script'
            }
            if (-not [string]::IsNullOrWhiteSpace($env:GH_TOKEN)) {
                $headers.Authorization = "Bearer $env:GH_TOKEN"
            }
            $release = Invoke-RestMethod -Uri "$GitHubApiUrl/releases/latest" -Headers $headers -TimeoutSec 300
        }
        catch {
            Fail 'could not resolve the latest stable release'
        }
        $version = $release.tag_name
        if ([string]::IsNullOrWhiteSpace($version)) {
            Fail 'latest release response did not contain a tag name'
        }
    }

    $version = $version -replace '^v', ''
    if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$') {
        Fail "unsupported version '$version'; expected 0.5.0 or a prerelease such as 0.5.0-rc.1"
    }
    return $version
}

function Get-Target {
    $architecture = $env:PROCESSOR_ARCHITEW6432
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        $architecture = $env:PROCESSOR_ARCHITECTURE
    }
    if ([string]::IsNullOrWhiteSpace($architecture)) {
        Fail "unsupported Windows architecture '$architecture'. Supported platforms: Windows x86_64 and Windows ARM64. For other platforms, use 'cargo install nemo-relay-cli'."
    }

    switch ($architecture.ToUpperInvariant()) {
        'AMD64' { return 'x86_64-pc-windows-msvc' }
        'X86_64' { return 'x86_64-pc-windows-msvc' }
        'ARM64' { return 'aarch64-pc-windows-msvc' }
        default { Fail "unsupported Windows architecture '$architecture'. Supported platforms: Windows x86_64 and Windows ARM64. For other platforms, use 'cargo install nemo-relay-cli'." }
    }
}

function Download-File([string]$Uri, [string]$Path) {
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $Path -UseBasicParsing -TimeoutSec 300
    }
    catch {
        Fail "could not download $Uri"
    }
}

function Try-Download-File([string]$Uri, [string]$Path) {
    # Used for the host's checksum, where a release that predates the host
    # answers 404 and that is a state to report rather than a failure to raise.
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $Path -UseBasicParsing -TimeoutSec 300
        return $true
    }
    catch {
        return $false
    }
}

function Assert-Checksum([string]$ChecksumFile, [string]$DownloadedFile, [string]$AssetName) {
    $expectedChecksum = ((Get-Content -LiteralPath $ChecksumFile -TotalCount 1).Trim() -split '\s+')[0].ToLowerInvariant()
    if ($expectedChecksum -notmatch '^[0-9a-f]{64}$') {
        Fail "invalid checksum file for $AssetName"
    }
    $actualChecksum = (Get-FileHash -LiteralPath $DownloadedFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualChecksum -ne $expectedChecksum) {
        Fail "checksum verification failed for $AssetName"
    }
}

function Promote-File([string]$Staged, [string]$Destination, [string]$Backup) {
    if (Test-Path -LiteralPath $Destination) {
        [System.IO.File]::Replace($Staged, $Destination, $Backup)
    }
    else {
        [System.IO.File]::Move($Staged, $Destination)
    }
}

function Add-ToPath([string]$Value, [string]$Directory) {
    foreach ($entry in ($Value -split ';')) {
        if ($entry -and [string]::Equals($entry.Trim().TrimEnd('\'), $Directory, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $Value
        }
    }
    if ([string]::IsNullOrEmpty($Value)) {
        return $Directory
    }
    return "$Value;$Directory"
}

function Add-InstallDirectoryToPath([string]$Directory) {
    $directory = [System.IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $userEnvironmentKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($null -eq $userEnvironmentKey) {
        Fail 'could not open the Windows user environment registry key'
    }
    try {
        $userPath = $userEnvironmentKey.GetValue(
            'Path',
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        if ($null -eq $userPath) {
            $userPath = ''
            $userPathKind = [Microsoft.Win32.RegistryValueKind]::String
        }
        else {
            $userPath = [string]$userPath
            $userPathKind = $userEnvironmentKey.GetValueKind('Path')
        }

        $updatedUserPath = Add-ToPath $userPath $directory
        if ($updatedUserPath -ne $userPath) {
            $userEnvironmentKey.SetValue('Path', $updatedUserPath, $userPathKind)
        }
    }
    finally {
        $userEnvironmentKey.Dispose()
    }
    $env:Path = Add-ToPath $env:Path $directory
}

if ($Help) {
    Show-Usage
    exit 0
}

try {
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            Fail 'LOCALAPPDATA must be set to choose the default install directory'
        }
        $InstallDir = Join-Path $env:LOCALAPPDATA 'nemo-relay\bin'
    }
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        Fail 'install directory must not be empty'
    }

    $version = Get-ReleaseVersion
    $target = Get-Target
    $asset = "nemo-relay-cli-$target-$version.exe"
    $assetUrl = "$GitHubUrl/releases/download/$version/$asset"
    $checksumUrl = "$assetUrl.sha256"
    # The host is the executable that runs a native plugin outside this process,
    # so an installation without one is an installation whose native plugins
    # cannot be isolated. It travels with the CLI from the release that publishes
    # it; a release that predates the host publishes nine assets and not ten, and
    # installing the CLI alone is then the most this installer can do — loudly,
    # because the runtime refuses to fall back to loading in process.
    $hostAsset = "nemo-plugin-host-$target-$version.exe"
    $hostAssetUrl = "$GitHubUrl/releases/download/$version/$hostAsset"
    $hostChecksumUrl = "$hostAssetUrl.sha256"

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
        Fail "install path is not a directory: $InstallDir"
    }
    $InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
    $downloadFile = Join-Path $InstallDir ".nemo-relay.download.$([guid]::NewGuid().ToString('N'))"
    $checksumFile = Join-Path $InstallDir ".nemo-relay.checksum.$([guid]::NewGuid().ToString('N'))"
    $hostDownloadFile = Join-Path $InstallDir ".nemo-relay.host.$([guid]::NewGuid().ToString('N'))"
    $hostChecksumFile = Join-Path $InstallDir ".nemo-relay.host-checksum.$([guid]::NewGuid().ToString('N'))"
    $backupFile = Join-Path $InstallDir ".nemo-relay.backup.$([guid]::NewGuid().ToString('N'))"
    $hostBackupFile = Join-Path $InstallDir ".nemo-relay.host-backup.$([guid]::NewGuid().ToString('N'))"
    $destination = Join-Path $InstallDir 'nemo-relay.exe'
    $hostDestination = Join-Path $InstallDir 'nemo-plugin-host.exe'
    $hostAvailable = $false

    try {
        Write-Output "Downloading NeMo Relay CLI $version for $target..."
        Download-File $assetUrl $downloadFile
        Download-File $checksumUrl $checksumFile
        Assert-Checksum $checksumFile $downloadFile $asset

        if (Try-Download-File $hostChecksumUrl $hostChecksumFile) {
            Download-File $hostAssetUrl $hostDownloadFile
            Assert-Checksum $hostChecksumFile $hostDownloadFile $hostAsset
            $hostAvailable = $true
        }

        # Everything is on disk and verified before either file is promoted, and
        # the host is promoted first: the CLI is the executable that decides
        # whether a host is started, so an upgrade interrupted between the two
        # moves leaves the old decider beside a new dependency rather than a new
        # decider beside an old one. Neither order can produce a silently
        # mismatched pair, because the handshake compares the release each was
        # built from before any plugin code loads.
        if ($hostAvailable) {
            Promote-File $hostDownloadFile $hostDestination $hostBackupFile
        }
        Promote-File $downloadFile $destination $backupFile
    }
    finally {
        Remove-Item -LiteralPath $downloadFile, $checksumFile, $hostDownloadFile, $hostChecksumFile, $backupFile, $hostBackupFile -Force -ErrorAction SilentlyContinue
    }

    Add-InstallDirectoryToPath $InstallDir
    Write-Output "Installed NeMo Relay CLI $version to $destination"
    if ($hostAvailable) {
        Write-Output "Installed the plugin host to $hostDestination"
    }
    else {
        Write-Warning "release $version does not publish $hostAsset (or it could not be fetched), so native plugins cannot be hosted outside this installation. Install a release that publishes the host, or set NEMO_RELAY_PLUGIN_HOST to a host built from this release."
    }
    Write-Output "Added $InstallDir to the Windows user PATH. Newly opened shells inherit this change."
}
catch {
    Write-Error $_
    exit 1
}
