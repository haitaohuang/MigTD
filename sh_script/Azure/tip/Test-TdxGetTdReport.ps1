#Requires -RunAsAdministrator

<#
.SYNOPSIS
  Request and verify a TDREPORT from a candidate MigTD on a physical TDX host.

.DESCRIPTION
  Starts the candidate MigTD HCS VM, generates a cryptographically random
  64-byte REPORTDATA nonce, and invokes the supported SVM API CLI contract:
  vm getmigtdreport -name <id> -reportdata <128 hex chars> -timeoutms <ms> -parse.
  The CLI must verify TDREPORT structure hashes and the REPORTDATA echo.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$IgvmFilePath,
    [string]$HashFilePath = "$IgvmFilePath.hash",
    [string]$HashEvidencePath,
    [string]$CandidateVmgsPath,
    [string]$SvmApiCliPath,
    [string]$MigTdId = 'tipmigtd-gettdreport',
    [string]$PowerTestPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerTest",
    [ValidateRange(1000, 120000)] [int]$TimeoutMs = 30000,
    [ValidateRange(1, 120)] [int]$RuntimeHashTimeoutSeconds = 15,
    [switch]$CaptureSerial = $true,
    [string]$EvidencePath = (Join-Path (Get-Location) 'gettdreport.evidence.json'),
    [switch]$SkipHashEvidenceValidation
)

$ErrorActionPreference = 'Stop'
$commonScript = Join-Path $PSScriptRoot 'TipHarness.Common.ps1'
if (-not (Test-Path $commonScript)) {
    throw "Harness helper not found: $commonScript"
}
. $commonScript

function Import-PowerTestFile {
    param([Parameter(Mandatory)] [string]$Name)

    $path = Join-Path $PowerTestPath $Name
    if (-not (Test-Path $path)) {
        throw (New-TipHarnessException 'PRECONDITION' "PowerTest module file not found: $path")
    }
    Import-Module $path -Global -Force -DisableNameChecking
}

function Resolve-SvmApiCli {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        if (-not (Test-Path -LiteralPath $RequestedPath -PathType Leaf)) {
            throw (New-TipHarnessException 'PRECONDITION' "SVM API CLI not found at explicit path: $RequestedPath")
        }
        return [pscustomobject]@{
            Path = (Resolve-Path -LiteralPath $RequestedPath).Path
            Source = 'explicit'
        }
    }

    foreach ($commandName in @('svmapi-cli.exe', 'hcscli.exe')) {
        $command = Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue
        if ($command) {
            return [pscustomobject]@{
                Path = $command.Source
                Source = "PATH:$commandName"
            }
        }
    }

    $installedCandidates = @(
        (Join-Path $env:ProgramFiles 'ACC-CVM-IgvmAgent\cli.exe'),
        (Join-Path $env:ProgramFiles 'IGVMAgent\cli.exe'),
        (Join-Path $env:ProgramData 'Microsoft\IGVMAgent\cli.exe')
    ) | Where-Object { $_ }
    foreach ($candidate in $installedCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [pscustomobject]@{
                Path = (Resolve-Path -LiteralPath $candidate).Path
                Source = 'installed-path'
            }
        }
    }

    throw (New-TipHarnessException 'PRECONDITION' 'SVM API CLI was not found. Pass -SvmApiCliPath with the built cli.exe; no fallback command was executed.')
}

function Convert-HexToBytes {
    param([Parameter(Mandatory)] [string]$Hex)

    if (($Hex.Length % 2) -ne 0 -or $Hex -notmatch '^[0-9a-fA-F]+$') {
        throw (New-TipHarnessException 'TEST_FAILURE' 'TDREPORT output contained invalid hexadecimal report data.')
    }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [Convert]::ToByte($Hex.Substring($index * 2, 2), 16)
    }
    return ,$bytes
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Convert-ToProcessArgument {
    param([Parameter(Mandatory)] [string]$Value)

    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ([regex]::Replace(
        $Value,
        '(\\*)"',
        { param($match) ($match.Groups[1].Value * 2) + '\"' }
    ) -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-SvmApiGetTdReport {
    param(
        [Parameter(Mandatory)] [string]$CliPath,
        [Parameter(Mandatory)] [string]$InstanceId,
        [Parameter(Mandatory)] [string]$ReportDataHex,
        [Parameter(Mandatory)] [int]$CliTimeoutMs
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $CliPath
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $arguments = @(
        'vm',
        'getmigtdreport',
        '-name',
        $InstanceId,
        '-reportdata',
        $ReportDataHex,
        '-timeoutms',
        [string]$CliTimeoutMs,
        '-parse'
    )
    $startInfo.Arguments = ($arguments | ForEach-Object {
        Convert-ToProcessArgument -Value ([string]$_)
    }) -join ' '

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw (New-TipHarnessException 'TRANSPORT' "Failed to start SVM API CLI: $CliPath")
    }

    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $processTimeoutMs = $CliTimeoutMs + 15000
        $timedOut = -not $process.WaitForExit($processTimeoutMs)
        if ($timedOut) {
            $process.Kill()
            $process.WaitForExit()
        }
        return [pscustomobject]@{
            ExitCode = if ($timedOut) { -1 } else { $process.ExitCode }
            TimedOut = $timedOut
            Stdout = $stdoutTask.GetAwaiter().GetResult()
            Stderr = $stderrTask.GetAwaiter().GetResult()
        }
    } finally {
        $process.Dispose()
    }
}

Import-Module Hyper-V -Force
foreach ($moduleName in @(
    'TdxLiveMigrationUtilities.psm1',
    'HCSUtilities.psm1',
    'VmgsUtilities.psm1',
    'WmiUtilities.psm1',
    'IVMUtilities.psm1'
)) {
    Import-PowerTestFile $moduleName
}

$hcsTest = Get-Module HCSTest
if ($hcsTest -and $hcsTest.NestedModules[0].Name -notlike '*.v2') {
    throw (New-TipHarnessException 'PRECONDITION' 'HCSTest v1 is already loaded. Close this PowerShell process and retry.')
}
if (-not $hcsTest) {
    Import-Module HCSTest -ArgumentList @{ UseVersion2 = $true } `
        -Global -Force -ErrorAction SilentlyContinue
    if (-not (Get-Module HCSTest)) {
        if (Get-Command Import-HcsTestModule -ErrorAction SilentlyContinue) {
            Import-HcsTestModule -UseVersion2
        } else {
            throw (New-TipHarnessException 'PRECONDITION' 'HCSTest is unavailable and HCSUtilities did not provide Import-HcsTestModule.')
        }
    }
}
if (-not (Get-Command New-HcsSystemDocument -ErrorAction SilentlyContinue)) {
    throw (New-TipHarnessException 'PRECONDITION' 'HCSTest v2 did not provide New-HcsSystemDocument.')
}
if (-not (Get-Command New-VmStateFile -ErrorAction SilentlyContinue)) {
    function global:New-VmStateFile {
        param(
            [Parameter(Mandatory)] [string]$GuestStateFilePath,
            [int]$FileSize = 16MB
        )

        $tool = Get-Command vmgstool.exe -ErrorAction SilentlyContinue
        if ($tool) {
            $tool = $tool.Source
        } elseif (Test-Path (Join-Path $env:SystemRoot 'System32\vmgstool.exe')) {
            $tool = Join-Path $env:SystemRoot 'System32\vmgstool.exe'
        }
        if ($tool) {
            & $tool -Create -FilePath $GuestStateFilePath "-FileSize=$FileSize" | Out-Null
        } elseif (Get-Command New-GuestStateFile -ErrorAction SilentlyContinue) {
            New-GuestStateFile -FilePath $GuestStateFilePath -FileSize $FileSize | Out-Null
        } else {
            throw (New-TipHarnessException 'PRECONDITION' 'Cannot create the MigTD guest state file: vmgstool.exe and New-GuestStateFile are unavailable.')
        }
    }
}

$hashEvidence = Resolve-TipMigTdHashFromFiles `
    -IgvmFilePath $IgvmFilePath `
    -HashFilePath $HashFilePath `
    -HashEvidencePath $HashEvidencePath `
    -SkipHashEvidenceValidation:$SkipHashEvidenceValidation
$resolvedCli = Resolve-SvmApiCli -RequestedPath $SvmApiCliPath
Write-Host "Using SVM API CLI ($($resolvedCli.Source)): $($resolvedCli.Path)"

$nonce = [byte[]]::new(64)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $rng.GetBytes($nonce)
} finally {
    $rng.Dispose()
}
$reportDataHex = ([BitConverter]::ToString($nonce) -replace '-', '').ToLowerInvariant()

$migTd = $null
$migTdCreation = $null
$serialJob = $null
$serialLogPath = $null
$runtimeMigTdHash = $null
$mappingAdded = $false
$scriptError = $null
$cleanupFailures = [System.Collections.Generic.List[string]]::new()
$resolvedEvidencePath = [System.IO.Path]::GetFullPath($EvidencePath)
try {
    $guestStateDirectory = Join-Path (Get-Location) 'guest-state'
    $migTdCreation = New-TipHcsMigTd `
        -Id $MigTdId `
        -IgvmFilePath $IgvmFilePath `
        -GuestStateDirectory $guestStateDirectory `
        -CandidateVmgsPath $CandidateVmgsPath `
        -CandidateEvidencePath (Join-Path (Get-Location) "$MigTdId.vmgs.evidence.json") `
        -EnableSerial:$CaptureSerial `
        -Force
    $migTd = $migTdCreation.Instance

    if ($CaptureSerial) {
        $serialLogPath = Join-Path (Get-Location) "$MigTdId.serial.log"
        Remove-Item $serialLogPath -ErrorAction SilentlyContinue
        $serialJob = Start-Job -Name "$MigTdId-serial" -ScriptBlock {
            param($PipeName, $LogPath)
            try {
                $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
                    '.',
                    $PipeName,
                    [System.IO.Pipes.PipeDirection]::In)
                $pipe.Connect(15000)
                $reader = [System.IO.StreamReader]::new($pipe)
                while ($true) {
                    $line = $reader.ReadLine()
                    if ($null -eq $line) {
                        break
                    }
                    Add-Content -Path $LogPath -Value $line
                }
            } catch {
                Add-Content -Path $LogPath -Value "[serial-capture] $_"
            }
        } -ArgumentList "raw$MigTdId", $serialLogPath
    }

    $migTd | Start-HcsSystem
    if ($CaptureSerial) {
        $runtimeMigTdHash = Wait-TipRuntimeHashFromSerialLog `
            -LogPath $serialLogPath `
            -TimeoutSeconds $RuntimeHashTimeoutSeconds `
            -ExpectedHash $hashEvidence.MigTdHash `
            -Context $MigTdId
    }
    Remove-VmHostMigrationTdMapping `
        -MigTdHash $hashEvidence.MigTdHash `
        -ErrorAction SilentlyContinue
    Add-VmHostMigrationTdMapping `
        -MigTdHash $hashEvidence.MigTdHash `
        -VmId $migTd.Id
    $mappingAdded = $true
    Set-VMHostMigrationPolicy DisabledByDefault $hashEvidence.MigTdHash

    $cliResult = Invoke-SvmApiGetTdReport `
        -CliPath $resolvedCli.Path `
        -InstanceId $MigTdId `
        -ReportDataHex $reportDataHex `
        -CliTimeoutMs $TimeoutMs

    $completionMatch = [regex]::Match($cliResult.Stdout, 'CompletionStatus:\s*(?<status>0x[0-9a-fA-F]+)')
    $reportMatch = [regex]::Match(
        $cliResult.Stdout,
        'ReportData \((?<length>\d+) bytes\):\s*(?<hex>[0-9a-fA-F]+)\s*Parsed TDREPORT',
        [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $hashVerificationPassed = $cliResult.Stdout -match 'Hash verification\s*:\s*PASS'
    $reportDataEchoPassed = $cliResult.Stdout -match 'REPORTDATA echo\s*:\s*PASS'
    $reportTypeMatch = [regex]::Match(
        $cliResult.Stdout,
        'REPORTTYPE\.TYPE\s*:\s*(?<type>0x[0-9a-fA-F]+)')

    $reportLengthBytes = $null
    $reportSha256 = $null
    $reportParseError = $null
    if ($reportMatch.Success) {
        try {
            $reportLengthBytes = [int]$reportMatch.Groups['length'].Value
            $reportBytes = Convert-HexToBytes -Hex $reportMatch.Groups['hex'].Value
            if ($reportBytes.Length -ne $reportLengthBytes) {
                $reportParseError = "Declared length $reportLengthBytes does not match parsed length $($reportBytes.Length)."
            } else {
                $reportSha256 = Get-Sha256Hex -Bytes $reportBytes
            }
        } catch {
            $reportParseError = $_.Exception.Message
        }
    }

    $stderrSummary = ([string]$cliResult.Stderr).Trim()
    if ($stderrSummary.Length -gt 2048) {
        $stderrSummary = $stderrSummary.Substring(0, 2048)
    }
    $verificationPassed = (
        -not $cliResult.TimedOut -and
        $cliResult.ExitCode -eq 0 -and
        $completionMatch.Success -and
        $completionMatch.Groups['status'].Value -match '^0x0+$' -and
        $reportMatch.Success -and
        -not $reportParseError -and
        $hashVerificationPassed -and
        $reportDataEchoPassed)
    $evidenceParent = Split-Path -Parent $resolvedEvidencePath
    if ($evidenceParent) {
        New-Item -ItemType Directory -Path $evidenceParent -Force | Out-Null
    }
    [ordered]@{
        schemaVersion = 1
        evidenceType = 'tdx-gettdreport'
        migTdId = $MigTdId
        migTdHash = $hashEvidence.MigTdHash
        runtimeMigTdHash = $runtimeMigTdHash
        cliPath = $resolvedCli.Path
        cliSource = $resolvedCli.Source
        cliSha256 = (Get-FileHash -LiteralPath $resolvedCli.Path -Algorithm SHA256).Hash.ToLowerInvariant()
        requestReportData = $reportDataHex
        timeoutMs = $TimeoutMs
        exitCode = $cliResult.ExitCode
        timedOut = [bool]$cliResult.TimedOut
        completionStatus = if ($completionMatch.Success) {
            $completionMatch.Groups['status'].Value.ToLowerInvariant()
        } else {
            $null
        }
        reportLengthBytes = $reportLengthBytes
        reportSha256 = $reportSha256
        reportParseError = $reportParseError
        reportType = if ($reportTypeMatch.Success) {
            $reportTypeMatch.Groups['type'].Value.ToLowerInvariant()
        } else {
            $null
        }
        hashVerificationPassed = [bool]$hashVerificationPassed
        reportDataEchoPassed = [bool]$reportDataEchoPassed
        verificationPassed = [bool]$verificationPassed
        stderrSummary = $stderrSummary
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resolvedEvidencePath

    if ($cliResult.TimedOut) {
        throw (New-TipHarnessException 'TRANSPORT' "SVM API CLI exceeded the $TimeoutMs ms request timeout plus process grace period.")
    }
    if ($cliResult.ExitCode -ne 0) {
        $category = if ($cliResult.ExitCode -eq 2) { 'TEST_FAILURE' } else { 'TRANSPORT' }
        throw (New-TipHarnessException $category "SVM API CLI getmigtdreport failed with exit code $($cliResult.ExitCode). Evidence: $resolvedEvidencePath")
    }
    if (-not $verificationPassed) {
        throw (New-TipHarnessException 'TEST_FAILURE' "SVM API CLI returned incomplete or failed TDREPORT verification evidence: $resolvedEvidencePath")
    }
}
catch {
    $scriptError = $_
}
finally {
    if ($mappingAdded) {
        try {
            Set-VMHostMigrationPolicy DisabledByDefault $hashEvidence.MigTdHash -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Set-VMHostMigrationPolicy DisabledByDefault failed: $($_.Exception.Message)")
        }
        try {
            Remove-VmHostMigrationTdMapping `
                -MigTdHash $hashEvidence.MigTdHash `
                -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Remove-VmHostMigrationTdMapping failed: $($_.Exception.Message)")
        }
    }
    if ($migTd) {
        try {
            Stop-HcsSystem $migTd -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Stop-HcsSystem $MigTdId failed: $($_.Exception.Message)")
        }
        try {
            $migTd.Close()
        } catch {
            $cleanupFailures.Add("Close MigTD handle $MigTdId failed: $($_.Exception.Message)")
        }
    }
    if ($migTdCreation) {
        try {
            Remove-TipCandidateVmgsCopy -MigTdCreation $migTdCreation
        } catch {
            $cleanupFailures.Add("Candidate VMGS cleanup for $MigTdId failed: $($_.Exception.Message)")
        }
    }
    if ($serialJob) {
        try {
            Wait-Job $serialJob -Timeout 5 -ErrorAction Stop | Out-Null
        } catch {
            $cleanupFailures.Add("Wait-Job $MigTdId-serial failed: $($_.Exception.Message)")
        }
        if ($serialJob.State -notin @('Completed', 'Failed')) {
            try {
                Stop-Job $serialJob -ErrorAction Stop | Out-Null
            } catch {
                $cleanupFailures.Add("Stop-Job $MigTdId-serial failed: $($_.Exception.Message)")
            }
        }
        try {
            Remove-Job $serialJob -Force -ErrorAction Stop
        } catch {
            $cleanupFailures.Add("Remove-Job $MigTdId-serial failed: $($_.Exception.Message)")
        }
    }
}

if ($cleanupFailures.Count -gt 0) {
    $cleanupMessage = $cleanupFailures -join '; '
    if ($scriptError) {
        throw (New-TipHarnessException 'CLEANUP' "$cleanupMessage | PrimaryError=$($scriptError.Exception.Message)")
    }
    throw (New-TipHarnessException 'CLEANUP' $cleanupMessage)
}
if ($scriptError) {
    throw $scriptError
}

[pscustomobject]@{
    CaseType = 'GetTdReport'
    Outcome = 'GetTdReportSuccess'
    MigTdId = $MigTdId
    MigTdHash = $hashEvidence.MigTdHash
    RuntimeMigTdHash = $runtimeMigTdHash
    HashEvidencePath = $hashEvidence.HashEvidencePath
    HashEvidenceVerified = [bool]$hashEvidence.EvidenceVerified
    SerialLogs = if ($serialLogPath) { @($serialLogPath) } else { @() }
    EvidenceFiles = @(
        $resolvedEvidencePath,
        $migTdCreation.CandidateVmgsEvidencePath
    ) | Where-Object { $_ }
}
