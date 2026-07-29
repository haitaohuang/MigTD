function New-TipHarnessException {
    param(
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Message
    )

    return [System.Exception]::new("[$Category] $Message")
}

function Get-TipHashEvidencePath {
    param([Parameter(Mandatory)] [string]$HashFilePath)

    return "$HashFilePath.evidence.json"
}

function Get-TipErrorCategory {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

    $text = [string]$ErrorRecord.Exception.Message
    $match = [regex]::Match($text, '^\[(?<category>[A-Z_]+)\]\s+')
    if ($match.Success) {
        return $match.Groups['category'].Value
    }
    return 'GENERIC_FAILURE'
}

function Convert-TipErrorRecordToString {
    param([Parameter(Mandatory)] [System.Management.Automation.ErrorRecord]$ErrorRecord)

    return ($ErrorRecord | Format-List * -Force | Out-String).Trim()
}

function Test-TipExpectedRejectionError {
    param([Parameter(Mandatory)] [object]$ErrorDetail)

    $text = [string]$ErrorDetail
    return $text -match 'MIGPOLICY_UNSATISFIED_ERROR|0x800721CE|external policy|policy unsatisfied|host permits'
}

function Resolve-TipMigTdHashFromFiles {
    param(
        [Parameter(Mandatory)] [string]$IgvmFilePath,
        [Parameter(Mandatory)] [string]$HashFilePath,
        [string]$HashEvidencePath,
        [switch]$SkipHashEvidenceValidation
    )

    if (-not (Test-Path $IgvmFilePath)) {
        throw (New-TipHarnessException 'PRECONDITION' "IGVM file not found: $IgvmFilePath")
    }
    if (-not (Test-Path $HashFilePath)) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Sibling hash file not found: $HashFilePath")
    }

    $migTdHash = (Get-Content $HashFilePath -Raw).Trim().ToLowerInvariant()
    if ($migTdHash -notmatch '^[0-9a-f]{96}$') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Sibling hash must be exactly 96 hexadecimal characters: $HashFilePath")
    }

    $evidencePath = if ($HashEvidencePath) {
        [System.IO.Path]::GetFullPath($HashEvidencePath)
    } else {
        Get-TipHashEvidencePath -HashFilePath $HashFilePath
    }
    if ($SkipHashEvidenceValidation) {
        return [pscustomobject]@{
            MigTdHash = $migTdHash
            HashFilePath = $HashFilePath
            HashEvidencePath = $evidencePath
            IgvmSha256 = $null
            EvidenceVerified = $false
        }
    }

    if (-not (Test-Path $evidencePath)) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Hash evidence file not found: $evidencePath")
    }

    try {
        $evidence = Get-Content $evidencePath -Raw | ConvertFrom-Json
    } catch {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Hash evidence is not valid JSON: $evidencePath")
    }

    if ([int]$evidence.schemaVersion -ne 1 -or [string]$evidence.evidenceType -ne 'igvm-sibling-hash') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Unsupported hash evidence schema in $evidencePath")
    }

    $evidenceHash = [string]$evidence.migTdInfoHash
    $evidenceSha256 = [string]$evidence.igvmSha256
    $evidenceIgvmName = [string]$evidence.igvmFileName

    if ($evidenceHash.ToLowerInvariant() -notmatch '^[0-9a-f]{96}$') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Evidence migTdInfoHash is invalid in $evidencePath")
    }
    if ($evidenceSha256.ToLowerInvariant() -notmatch '^[0-9a-f]{64}$') {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Evidence igvmSha256 is invalid in $evidencePath")
    }
    if ($evidenceIgvmName -and $evidenceIgvmName -ne (Split-Path $IgvmFilePath -Leaf)) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Evidence igvmFileName mismatch in $evidencePath. Expected $(Split-Path $IgvmFilePath -Leaf) Found $evidenceIgvmName")
    }

    $igvmSha256 = (Get-FileHash -Path $IgvmFilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($igvmSha256 -ne $evidenceSha256.ToLowerInvariant()) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "IGVM SHA256 mismatch for $IgvmFilePath. Evidence=$evidenceSha256 Actual=$igvmSha256")
    }
    if ($migTdHash -ne $evidenceHash.ToLowerInvariant()) {
        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Sibling hash mismatch for $IgvmFilePath. HashFile=$migTdHash Evidence=$evidenceHash")
    }

    return [pscustomobject]@{
        MigTdHash = $migTdHash
        HashFilePath = $HashFilePath
        HashEvidencePath = $evidencePath
        IgvmSha256 = $igvmSha256
        EvidenceVerified = $true
    }
}

function Resolve-TipCandidateVmgs {
    param([Parameter(Mandatory)] [string]$CandidateVmgsPath)

    if (-not (Test-Path -LiteralPath $CandidateVmgsPath -PathType Leaf)) {
        throw (New-TipHarnessException 'PRECONDITION' "Candidate VMGS file not found: $CandidateVmgsPath")
    }

    $item = Get-Item -LiteralPath $CandidateVmgsPath
    if ($item.Length -le 0) {
        throw (New-TipHarnessException 'PRECONDITION' "Candidate VMGS file is empty: $($item.FullName)")
    }

    return [pscustomobject]@{
        SourcePath = $item.FullName
        LengthBytes = [long]$item.Length
        Sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Test-TipCandidateVmgsSourcePreserved {
    param([Parameter(Mandatory)] [object]$CandidateVmgs)

    $current = Resolve-TipCandidateVmgs -CandidateVmgsPath $CandidateVmgs.SourcePath
    if ($current.LengthBytes -ne $CandidateVmgs.LengthBytes -or
        $current.Sha256 -ne $CandidateVmgs.Sha256) {
        throw (New-TipHarnessException 'CLEANUP' "Packaged candidate VMGS changed during the test: $($CandidateVmgs.SourcePath)")
    }
}

function New-TipHcsMigTd {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$IgvmFilePath,
        [Parameter(Mandatory)] [string]$GuestStateDirectory,
        [string]$CandidateVmgsPath,
        [string]$CandidateEvidencePath,
        [switch]$EnableSerial,
        [switch]$Force
    )

    $guestStateDirectoryPath = [System.IO.Path]::GetFullPath($GuestStateDirectory)
    New-Item -ItemType Directory -Path $guestStateDirectoryPath -Force | Out-Null
    $guestStateFilePath = Join-Path $guestStateDirectoryPath "$Id.vmgs"

    if (-not $CandidateVmgsPath) {
        $instance = New-TestHcsMigTd `
            -Id $Id `
            -IgvmFilePath (Resolve-Path -LiteralPath $IgvmFilePath).Path `
            -GuestStateDirectory $guestStateDirectoryPath `
            -EnableSerial:$EnableSerial `
            -Force:$Force
        return [pscustomobject]@{
            Instance = $instance
            GuestStateFilePath = $guestStateFilePath
            CandidateVmgs = $null
            CandidateVmgsEvidencePath = $null
        }
    }

    $candidate = Resolve-TipCandidateVmgs -CandidateVmgsPath $CandidateVmgsPath
    if ([System.StringComparer]::OrdinalIgnoreCase.Equals(
        $candidate.SourcePath,
        [System.IO.Path]::GetFullPath($guestStateFilePath))) {
        throw (New-TipHarnessException 'PRECONDITION' 'Candidate VMGS source must not be the per-case guest-state destination.')
    }

    if (Test-Path -LiteralPath $guestStateFilePath) {
        if (-not $Force) {
            throw (New-TipHarnessException 'PRECONDITION' "Guest state file already exists; use -Force to replace: $guestStateFilePath")
        }
        Remove-Item -LiteralPath $guestStateFilePath -Force
    }

    try {
        Copy-Item -LiteralPath $candidate.SourcePath -Destination $guestStateFilePath
        $copy = Get-Item -LiteralPath $guestStateFilePath
        $copySha256 = (Get-FileHash -LiteralPath $copy.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($copy.Length -le 0 -or
            $copy.Length -ne $candidate.LengthBytes -or
            $copySha256 -ne $candidate.Sha256) {
            throw (New-TipHarnessException 'PRECONDITION' "Candidate VMGS copy verification failed: $guestStateFilePath")
        }
        Test-TipCandidateVmgsSourcePreserved -CandidateVmgs $candidate

        $resolvedIgvmFilePath = (Resolve-Path -LiteralPath $IgvmFilePath).Path
        Grant-VmGroupAccess $resolvedIgvmFilePath | Out-Null
        Grant-VmGroupAccess $guestStateFilePath | Out-Null

        $doc = New-HcsSystemDocument -Owner $Id -VirtualMachine
        $doc.SchemaVersion.Major = 2
        $doc.SchemaVersion.Minor = 1
        $doc.ShouldTerminateOnLastHandleClosed = $true
        $doc.VirtualMachine.ComputeTopology.Memory.Backing =
            [HCS.Schema.VirtualMachines.Resources.Compute.MemoryBackingType]::Physical
        $doc.VirtualMachine.ComputeTopology.Processor.Count = 1
        $doc.VirtualMachine.ComputeTopology.Memory.SizeInMB = 512
        $doc.VirtualMachine.ComputeTopology.Memory.AllowOvercommit = $false

        $isolationType = [HCS.Schema.VirtualMachines.GuestIsolationType]::TrustDomain
        $doc = Add-HcsSystemDocumentIsolated `
            -SystemDocument $doc `
            -IsolationType $isolationType `
            -VmgsFilePath $guestStateFilePath
        $doc.VirtualMachine.Version.Major = 12
        $doc.VirtualMachine.Version.Minor = 5

        if ($EnableSerial) {
            $port = [HCS.Schema.VirtualMachines.Resources.ComPort]::new()
            $port.NamedPipe = "\\.\pipe\raw$Id"
            $port.OptimizeForDebugger = $true
            $ports = [System.Collections.Generic.Dictionary[uint32, HCS.Schema.VirtualMachines.Resources.ComPort]]::new()
            $ports.Add(0, $port)
            $doc.VirtualMachine.Devices.COMPorts = $ports
        }

        $doc.VirtualMachine.SecuritySettings.Isolation.HclEnabled = $false
        $doc.VirtualMachine.SecuritySettings.Isolation.IgvmFilePath =
            $resolvedIgvmFilePath
        $doc.VirtualMachine.Devices.GhciDevice = @{
            LogLevel = [HCS.Schema.VirtualMachines.Resources.GhciLogLevel]::Trace
        }

        $resolvedEvidencePath = $null
        if ($CandidateEvidencePath) {
            $resolvedEvidencePath = [System.IO.Path]::GetFullPath($CandidateEvidencePath)
            $evidenceParent = Split-Path -Parent $resolvedEvidencePath
            if ($evidenceParent) {
                New-Item -ItemType Directory -Path $evidenceParent -Force | Out-Null
            }
            [ordered]@{
                schemaVersion = 1
                evidenceType = 'candidate-vmgs-copy'
                sourcePath = $candidate.SourcePath
                sourceLengthBytes = $candidate.LengthBytes
                sourceSha256 = $candidate.Sha256
                copyPath = $copy.FullName
                copyLengthBytes = [long]$copy.Length
                copySha256 = $copySha256
                sourcePreserved = $true
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resolvedEvidencePath
        }

        $instance = New-HcsSystem -Id $Id -SystemDocument $doc

        return [pscustomobject]@{
            Instance = $instance
            GuestStateFilePath = $copy.FullName
            CandidateVmgs = $candidate
            CandidateVmgsEvidencePath = $resolvedEvidencePath
        }
    } catch {
        $primaryError = $_
        if (Test-Path -LiteralPath $guestStateFilePath) {
            try {
                Remove-Item -LiteralPath $guestStateFilePath -Force -ErrorAction Stop
            } catch {
                throw (New-TipHarnessException 'CLEANUP' "Candidate VMGS copy cleanup failed: $guestStateFilePath | PrimaryError=$($primaryError.Exception.Message)")
            }
        }
        throw $primaryError
    }
}

function Remove-TipCandidateVmgsCopy {
    param([object]$MigTdCreation)

    if (-not $MigTdCreation -or -not $MigTdCreation.CandidateVmgs) {
        return
    }

    Test-TipCandidateVmgsSourcePreserved -CandidateVmgs $MigTdCreation.CandidateVmgs
    if (Test-Path -LiteralPath $MigTdCreation.GuestStateFilePath) {
        Remove-Item -LiteralPath $MigTdCreation.GuestStateFilePath -Force
    }
}

function Get-TipRuntimeHashRegexes {
    return @(
        'Current TDX migration policy hash:\s*([0-9a-fA-F]{96})',
        'TD Info Hash:\s*([0-9a-fA-F]{96})',
        'Current migration policy:\s*([0-9a-fA-F]{96})'
    )
}

function Get-TipRuntimeHashesFromSerialText {
    param([Parameter(Mandatory)] [string]$Text)

    $hashes = [System.Collections.Generic.List[string]]::new()
    foreach ($pattern in (Get-TipRuntimeHashRegexes)) {
        foreach ($match in [regex]::Matches($Text, $pattern)) {
            if ($match.Success) {
                $hash = $match.Groups[1].Value.ToLowerInvariant()
                if ($hash -match '^[0-9a-f]{96}$') {
                    $hashes.Add($hash)
                }
            }
        }
    }
    return @($hashes | Select-Object -Unique)
}

function Wait-TipRuntimeHashFromSerialLog {
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [Parameter(Mandatory)] [int]$TimeoutSeconds,
        [string]$ExpectedHash,
        [string]$Context = 'MigTD'
    )

    $expected = if ($ExpectedHash) { $ExpectedHash.Trim().ToLowerInvariant() } else { $null }
    if ($expected -and $expected -notmatch '^[0-9a-f]{96}$') {
        throw (New-TipHarnessException 'PRECONDITION' "ExpectedHash must be 96 hex chars for $Context.")
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (Test-Path $LogPath) {
            $text = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
            if ($text) {
                $hashes = @(Get-TipRuntimeHashesFromSerialText -Text $text)
                if ($hashes.Count -gt 0) {
                    $actual = $hashes[-1]
                    if ($expected -and $actual -ne $expected) {
                        throw (New-TipHarnessException 'MISSING_EVIDENCE' "Runtime TD Info Hash mismatch for '$Context'. Expected=$expected Runtime=$actual Log=$LogPath")
                    }
                    return $actual
                }
            }
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    throw (New-TipHarnessException 'MISSING_EVIDENCE' "Runtime TD Info Hash not found for '$Context' in $LogPath within $TimeoutSeconds seconds.")
}
