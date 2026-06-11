<#
.SYNOPSIS
    Sync Copilot Chat memory between VS Code AppData and the workspace backup.

.DESCRIPTION
    VS Code Copilot Chat stores memory in two locations:
      - Repo-scoped (default for this script):
          %APPDATA%\Code\User\workspaceStorage\<workspace-hash>\GitHub.copilot-chat\memory-tool\memories\repo\
      - User-scoped (opt-in via -IncludeUserMemory):
          %APPDATA%\Code\User\globalStorage\github.copilot-chat\memory-tool\memories\

    Neither path is in git. If VS Code is reinstalled, AppData is wiped, or the
    workspace is renamed (hash changes for repo memory), the contents are lost.

    This script keeps a workspace-local backup at notes\memory\ (gitignored).
    Because the backup lives inside the workspace folder, any cloud sync attached
    to that folder (OneDrive, Dropbox, iCloud, Google Drive, etc.) will pick it up
    automatically. The default direction is ToBackup (export only). See SECURITY.

.PARAMETER Direction
    ToBackup   (default) Copy AppData -> workspace backup. Safe.
    FromBackup Copy workspace backup -> AppData. Trusted-input mode. See SECURITY.
    Both       Newest file wins in each direction. Implies FromBackup risks.

.PARAMETER IncludeUserMemory
    Also sync GLOBAL user memory (notes\memory\user\). Off by default because user
    memory affects every workspace and every chat across the machine, not just this
    workspace. See SECURITY.

.PARAMETER IncludeCopilotCli
    Also sync the GitHub Copilot CLI / desktop app memory store at
    %USERPROFILE%\.copilot\memories\ (a SEPARATE store from VS Code). Adds two tiers
    that share the same notes\memory backup as the VS Code tiers, so the workspace
    backup becomes a common hub keeping both engines consistent:
      - cli-repo : %USERPROFILE%\.copilot\memories\repo\  <-> notes\memory\repo
      - cli-user : %USERPROFILE%\.copilot\memories\ (top-level *.md only, NOT recursive
                   so repo\ and session\ subfolders are left alone) <-> notes\memory\user
    Off by default. The CLI store is machine-global (not workspace-hash-scoped), so on
    FromBackup/Both it influences every Copilot CLI session on this machine. See SECURITY.
    Can be combined with the VS Code tiers; if no VS Code workspace hash is found this
    switch lets the script proceed with the CLI tiers alone.

.PARAMETER Force
    Required for FromBackup and Both. Acknowledges that backup contents will be
    written into Copilot's trusted memory store and treated as authoritative
    instructions in every future chat session.

.PARAMETER Variant
    VS Code variant to target: Auto (default), Stable, or Insiders.
    Auto-detection searches BOTH variants for the workspace hash:
      - Found in one  -> uses it
      - Found in both -> prefers the variant that launched the script
        (via TERM_PROGRAM_VERSION env var); prompts when run outside VS Code
      - Found in none -> errors with the searched paths
    Pin explicitly to skip the prompt in scheduled tasks or CI.

.NOTES
    SECURITY:
    Memory is loaded into Copilot Chat as authoritative instructions with access
    to MCP tools (Sentinel, Graph, Azure). Anything synced via -Direction
    FromBackup will influence future chats:
      - Repo memory  -> influences chats in THIS workspace only
      - User memory  -> influences chats in EVERY workspace on this machine
    Treat backups the same as code: review diffs before pulling from another
    machine, fork, or PR. Never accept memory files from untrusted sources.
    The default ToBackup direction is one-way and cannot overwrite Copilot's
    memory.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('ToBackup', 'FromBackup', 'Both')]
    [string]$Direction = 'ToBackup',

    [switch]$IncludeUserMemory,

    [switch]$IncludeCopilotCli,

    [switch]$Force,

    [ValidateSet('Auto', 'Stable', 'Insiders')]
    [string]$Variant = 'Auto'
)

$ErrorActionPreference = 'Stop'

if ($Direction -in 'FromBackup','Both' -and -not $Force -and -not $WhatIfPreference) {
    Write-Host ""
    Write-Host "REFUSED: -Direction $Direction writes into Copilot's trusted memory store." -ForegroundColor Red
    Write-Host "Anything in notes\memory\repo\ will become authoritative instructions in every" -ForegroundColor Yellow
    Write-Host "future Copilot Chat session in this workspace." -ForegroundColor Yellow
    if ($IncludeUserMemory) {
        Write-Host "With -IncludeUserMemory, notes\memory\user\ ALSO writes into GLOBAL user memory" -ForegroundColor Yellow
        Write-Host "and will influence chats in EVERY workspace on this machine." -ForegroundColor Yellow
    }
    if ($IncludeCopilotCli) {
        Write-Host "With -IncludeCopilotCli, the GitHub Copilot CLI memory store (%USERPROFILE%\.copilot\" -ForegroundColor Yellow
        Write-Host "memories\) is machine-global and will influence EVERY Copilot CLI session on this machine." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Re-run with -Force to acknowledge, or -WhatIf to preview." -ForegroundColor Yellow
    Write-Host "Default direction (ToBackup) is one-way and safe." -ForegroundColor Cyan
    return
}

$WorkspaceRoot = (Resolve-Path (Split-Path -Parent $PSScriptRoot)).Path

$RepoMemorySubpath = 'GitHub.copilot-chat\memory-tool\memories\repo'

# --- Detect VS Code variant (Stable vs Insiders) ---
function Get-WorkspaceMatches {
    param([string]$StorageRoot, [string]$WorkspaceRootPath)
    $found = @()
    if (-not (Test-Path $StorageRoot)) { return ,$found }
    foreach ($hash in (Get-ChildItem $StorageRoot -Directory -ErrorAction SilentlyContinue)) {
        $workspaceJson = Join-Path $hash.FullName 'workspace.json'
        if (-not (Test-Path $workspaceJson)) { continue }
        try {
            $cfg = Get-Content $workspaceJson -Raw | ConvertFrom-Json
            if ($cfg.folder) {
                $decoded = [System.Uri]::UnescapeDataString($cfg.folder) -replace '^file:///','' -replace '/','\'
                if ($decoded.TrimEnd('\') -ieq $WorkspaceRootPath.TrimEnd('\')) {
                    $found += $hash
                }
            }
        } catch {
            # Skip malformed workspace.json
        }
    }
    return ,$found
}

# Hint from VS Code-injected env vars (only set inside an integrated terminal)
$EnvHint = $null
if ($env:TERM_PROGRAM -eq 'vscode' -and $env:TERM_PROGRAM_VERSION) {
    $EnvHint = if ($env:TERM_PROGRAM_VERSION -like '*insider*') { 'Code - Insiders' } else { 'Code' }
}

# Restrict candidates if user pinned -Variant
$VariantCandidates = switch ($Variant) {
    'Stable'   { @('Code') }
    'Insiders' { @('Code - Insiders') }
    default    { @('Code', 'Code - Insiders') }
}

$VariantMatches = [ordered]@{}
foreach ($v in $VariantCandidates) {
    $storage = Join-Path $env:APPDATA "$v\User\workspaceStorage"
    $hashes = Get-WorkspaceMatches -StorageRoot $storage -WorkspaceRootPath $WorkspaceRoot
    if ($hashes.Count -gt 0) { $VariantMatches[$v] = $hashes }
}

$VsCodeAvailable = $VariantMatches.Count -gt 0

if (-not $VsCodeAvailable) {
    $searched = ($VariantCandidates | ForEach-Object { "  - " + (Join-Path $env:APPDATA "$_\User\workspaceStorage") }) -join "`n"
    if ($IncludeCopilotCli) {
        Write-Warning "No VS Code workspaceStorage hash matched $WorkspaceRoot. Searched:`n$searched`nProceeding with Copilot CLI tiers only (-IncludeCopilotCli)."
    } else {
        throw "Could not find a workspaceStorage hash matching $WorkspaceRoot. Searched:`n$searched`nOpen the workspace in VS Code (or VS Code Insiders) at least once, or pass -Variant explicitly. (Or pass -IncludeCopilotCli to sync only the Copilot CLI memory store.)"
    }
}

$Tiers = @()

if ($VsCodeAvailable) {
    if ($VariantMatches.Count -eq 1) {
        $VsCodeVariant = @($VariantMatches.Keys)[0]
        if ($EnvHint -and $EnvHint -ne $VsCodeVariant) {
            Write-Warning "Script launched from $EnvHint, but workspace hash only exists for $VsCodeVariant. Using $VsCodeVariant."
        }
    } else {
        # Hash matches in BOTH variants
        if ($EnvHint -and $VariantMatches.Contains($EnvHint)) {
            $VsCodeVariant = $EnvHint
            Write-Host "Workspace exists in both Stable and Insiders. Using $EnvHint (script launched from that variant)." -ForegroundColor Yellow
        } else {
            Write-Host ""
            Write-Host "Workspace hash matches in BOTH VS Code variants:" -ForegroundColor Yellow
            foreach ($v in $VariantMatches.Keys) {
                $h = $VariantMatches[$v] | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
                Write-Host "  $v : $($h.Name)  (last modified $($h.LastWriteTimeUtc.ToString('u')))" -ForegroundColor Yellow
            }
            Write-Host ""
            if (-not [Environment]::UserInteractive) {
                throw "Workspace hash matches both 'Code' and 'Code - Insiders'. Re-run with -Variant Stable or -Variant Insiders (non-interactive session, cannot prompt)."
            }
            Write-Host "Tip: re-run with -Variant Stable or -Variant Insiders to skip this prompt." -ForegroundColor DarkGray
            $choice = (Read-Host "Select variant [S]table / [I]nsiders / [Q]uit").Trim().ToUpper()
            switch -Regex ($choice) {
                '^I' { $VsCodeVariant = 'Code - Insiders' }
                '^S' { $VsCodeVariant = 'Code' }
                default { Write-Host "Cancelled." -ForegroundColor DarkGray; return }
            }
        }
    }

    $WorkspaceStorageRoot = Join-Path $env:APPDATA "$VsCodeVariant\User\workspaceStorage"
    $MatchingHashes = $VariantMatches[$VsCodeVariant]

    Write-Host "VS Code variant: $VsCodeVariant" -ForegroundColor DarkGray

    if ($MatchingHashes.Count -gt 1) {
        Write-Warning "Multiple workspaceStorage hashes match this workspace folder in ${VsCodeVariant}:"
        $MatchingHashes | ForEach-Object { Write-Warning "  - $($_.Name) (last modified $($_.LastWriteTimeUtc.ToString('u')))" }
        Write-Warning "Using the most recently modified. Clean up stale entries in $WorkspaceStorageRoot if this is wrong."
        $MatchedHash = $MatchingHashes | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    } else {
        $MatchedHash = $MatchingHashes[0]
    }

    $Tiers += @{
        Label   = 'repo'
        AppData = Join-Path $MatchedHash.FullName $RepoMemorySubpath
        Backup  = Join-Path $WorkspaceRoot 'notes\memory\repo'
        Scope   = "workspace ($($MatchedHash.Name))"
        Recurse = $true
    }

    if ($IncludeUserMemory) {
        $Tiers += @{
            Label   = 'user'
            AppData = Join-Path $env:APPDATA "$VsCodeVariant\User\globalStorage\github.copilot-chat\memory-tool\memories"
            Backup  = Join-Path $WorkspaceRoot 'notes\memory\user'
            Scope   = 'GLOBAL (every workspace on this machine)'
            Recurse = $true
        }
    }
}

if ($IncludeCopilotCli) {
    # GitHub Copilot CLI / desktop app keeps a SEPARATE, machine-global memory store.
    # Both CLI tiers share the same notes\memory backup as the VS Code tiers, so the
    # backup acts as a common hub that keeps VS Code and the Copilot CLI consistent.
    $CliRoot = Join-Path $env:USERPROFILE '.copilot\memories'
    $Tiers += @{
        Label   = 'cli-repo'
        AppData = Join-Path $CliRoot 'repo'
        Backup  = Join-Path $WorkspaceRoot 'notes\memory\repo'
        Scope   = 'Copilot CLI (this machine, repo memory)'
        Recurse = $true
    }
    # Non-recursive: only top-level *.md (the context-check triggers). This avoids
    # dragging the repo\ and session\ subfolders of the CLI store into the user tier.
    $Tiers += @{
        Label   = 'cli-user'
        AppData = $CliRoot
        Backup  = Join-Path $WorkspaceRoot 'notes\memory\user'
        Scope   = 'Copilot CLI GLOBAL user memory (this machine)'
        Recurse = $false
    }
}

if ($Tiers.Count -eq 0) {
    throw "No tiers selected to sync."
}

Write-Host "Direction      : $Direction" -ForegroundColor Cyan
Write-Host "Tiers          : $(($Tiers | ForEach-Object { $_.Label }) -join ', ')" -ForegroundColor Cyan
Write-Host ""

$ExcludePatterns = @('README*', '_*', '.*')

function Test-Excluded {
    param([string]$FileName)
    foreach ($pattern in $ExcludePatterns) {
        if ($FileName -like $pattern) { return $true }
    }
    return $false
}

function Test-PathContained {
    param([string]$Candidate, [string]$Root)
    try {
        $full = [System.IO.Path]::GetFullPath($Candidate)
        $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
        return $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

$Stats = [ordered]@{ Copied = 0; Skipped = 0; Errors = 0; Excluded = 0; Blocked = 0 }

function Copy-IfNewer {
    param([string]$Source, [string]$Target, [string]$TargetRoot, [string]$Label)
    try {
        if (-not (Test-PathContained -Candidate $Target -Root $TargetRoot)) {
            Write-Warning "  [BLOCKED] $Source -> $Target (escapes $TargetRoot)"
            $Stats.Blocked++
            return
        }
        $srcInfo = Get-Item $Source -ErrorAction Stop
        $tgtInfo = if (Test-Path $Target) { Get-Item $Target -ErrorAction Stop } else { $null }

        $shouldCopy = $false
        $reason = ""
        if (-not $tgtInfo) {
            $shouldCopy = $true; $reason = "new"
        } elseif ($srcInfo.LastWriteTimeUtc -gt $tgtInfo.LastWriteTimeUtc) {
            $shouldCopy = $true
            $reason = "newer ($([int]($srcInfo.LastWriteTimeUtc - $tgtInfo.LastWriteTimeUtc).TotalMinutes)m)"
        }

        if (-not $shouldCopy) { $Stats.Skipped++; return }

        if ($PSCmdlet.ShouldProcess($Target, "Copy $Label ($reason)")) {
            $targetDir = Split-Path -Parent $Target
            if (-not (Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
            Copy-Item $Source $Target -Force -ErrorAction Stop
            Write-Host "  [$Label] $($srcInfo.Name) ($reason)" -ForegroundColor Green
            $Stats.Copied++
        }
    } catch {
        Write-Warning "  [ERROR] $Source -> $Target : $($_.Exception.Message)"
        $Stats.Errors++
    }
}

function Sync-Tier {
    param(
        [string]$TierLabel,
        [string]$AppDataPath,
        [string]$BackupPath,
        [string]$Scope,
        [bool]$Recurse = $true
    )

    Write-Host "===== Tier: $TierLabel ($Scope) =====" -ForegroundColor Cyan
    Write-Host "  AppData : $AppDataPath" -ForegroundColor DarkGray
    Write-Host "  Backup  : $BackupPath" -ForegroundColor DarkGray
    if (-not $Recurse) { Write-Host "  (top-level files only - not recursive)" -ForegroundColor DarkGray }

    if (-not (Test-Path $AppDataPath)) {
        Write-Warning "  AppData folder does not exist yet: $AppDataPath"
        if ($Direction -eq 'ToBackup') {
            Write-Host "  (skipping tier - nothing to export)" -ForegroundColor DarkGray
            Write-Host ""
            return
        }
        if ($PSCmdlet.ShouldProcess($AppDataPath, "Create empty AppData folder")) {
            New-Item -ItemType Directory -Path $AppDataPath -Force | Out-Null
        }
    }
    if (-not (Test-Path $BackupPath)) {
        if ($PSCmdlet.ShouldProcess($BackupPath, "Create empty backup folder")) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        }
    }

    $AppDataFull = if (Test-Path $AppDataPath) { (Resolve-Path $AppDataPath).Path } else { $AppDataPath }
    $BackupFull  = if (Test-Path $BackupPath)  { (Resolve-Path $BackupPath).Path }  else { $BackupPath }

    $RecurseArgs = if ($Recurse) { @{ Recurse = $true } } else { @{} }

    if ($Direction -in 'Both','ToBackup') {
        Write-Host "  AppData -> Backup:" -ForegroundColor Yellow
        $found = 0
        Get-ChildItem -Path $AppDataFull -File @RecurseArgs -ErrorAction SilentlyContinue | ForEach-Object {
            $found++
            if (Test-Excluded $_.Name) {
                Write-Host "    [skip] $($_.Name) (doc/excluded)" -ForegroundColor DarkGray
                $Stats.Excluded++
                return
            }
            $rel = $_.FullName.Substring($AppDataFull.Length).TrimStart('\')
            $tgt = Join-Path $BackupFull $rel
            Copy-IfNewer -Source $_.FullName -Target $tgt -TargetRoot $BackupFull -Label '->'
        }
        if ($found -eq 0) { Write-Host "    (no files in AppData)" -ForegroundColor DarkGray }
    }

    if ($Direction -in 'Both','FromBackup') {
        Write-Host "  Backup -> AppData:" -ForegroundColor Yellow
        $found = 0
        Get-ChildItem -Path $BackupFull -File @RecurseArgs -ErrorAction SilentlyContinue | ForEach-Object {
            $found++
            if (Test-Excluded $_.Name) {
                Write-Host "    [skip] $($_.Name) (doc/excluded)" -ForegroundColor DarkGray
                $Stats.Excluded++
                return
            }
            $rel = $_.FullName.Substring($BackupFull.Length).TrimStart('\')
            $tgt = Join-Path $AppDataFull $rel
            Copy-IfNewer -Source $_.FullName -Target $tgt -TargetRoot $AppDataFull -Label '<-'
        }
        if ($found -eq 0) { Write-Host "    (no files in backup folder)" -ForegroundColor DarkGray }
    }
    Write-Host ""
}

foreach ($tier in $Tiers) {
    $tierRecurse = if ($tier.ContainsKey('Recurse')) { [bool]$tier.Recurse } else { $true }
    Sync-Tier -TierLabel $tier.Label -AppDataPath $tier.AppData -BackupPath $tier.Backup -Scope $tier.Scope -Recurse $tierRecurse
}

Write-Host "Done. Copied: $($Stats.Copied)  Skipped: $($Stats.Skipped)  Excluded: $($Stats.Excluded)  Blocked: $($Stats.Blocked)  Errors: $($Stats.Errors)" -ForegroundColor Cyan
if ($Stats.Errors -gt 0 -or $Stats.Blocked -gt 0) {
    Write-Warning "Completed with $($Stats.Errors) error(s) and $($Stats.Blocked) blocked path(s) - review output above."
    exit 1
}
