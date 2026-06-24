[CmdletBinding()]
param(
    [Parameter()]
    [string] $DatabasePath = (Join-Path $PSScriptRoot 'spyware-db.json'),

    [Parameter()]
    [switch] $ValidateOnly,

    [Parameter()]
    [switch] $AuditOnly,

    [Parameter()]
    [string] $ApplyIds,

    [Parameter()]
    [string] $BackupDirectory,

    [Parameter()]
    [switch] $NonInteractive
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ToolVersion = '1.0.2'
$script:LogPath = $null
$script:ChangeHistoryPath = $null
$script:LastOperationResult = $null
$script:IgnoreListPath = $null
$script:OperationFailures = 0

function Write-Section {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Title
    )

    Write-Host ''
    Write-Host ('=' * 92) -ForegroundColor DarkCyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ('=' * 92) -ForegroundColor DarkCyan
}

function Write-OperationResult {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'SKIP', 'FAIL', 'INFO')]
        [string] $Status,

        [Parameter(Mandatory = $true)]
        [string] $Message
    )

    $line = '[{0}] {1}' -f $Status, $Message
    $script:LastOperationResult = [PSCustomObject]@{
        Status    = $Status
        Message   = $Message
        Timestamp = (Get-Date -Format o)
    }

    switch ($Status) {
        'OK' {
            Write-Host $line -ForegroundColor Green
        }
        'SKIP' {
            Write-Host $line -ForegroundColor Yellow
        }
        'FAIL' {
            $script:OperationFailures++
            Write-Host $line -ForegroundColor Red
        }
        default {
            Write-Host $line
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        try {
            Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
        }
        catch {
            Write-Host ('[WARN] Could not write to log: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Test-ObjectProperty {
    param(
        [Parameter(Mandatory = $true)]
        [object] $InputObject,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object] $InputObject,

        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter()]
        $DefaultValue = $null
    )

    $property = $InputObject.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return $DefaultValue
    }

    return $property.Value
}

function ConvertTo-PowerShellSingleQuotedString {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Value
    )

    return "'{0}'" -f $Value.Replace("'", "''")
}

function ConvertTo-PowerShellLiteral {
    param(
        [Parameter(Mandatory = $true)]
        $Value
    )

    if ($Value -is [bool]) {
        if ($Value) {
            return '$true'
        }

        return '$false'
    }

    if ($Value -is [int] -or $Value -is [long]) {
        return [string]$Value
    }

    return ConvertTo-PowerShellSingleQuotedString -Value ([string]$Value)
}

function Convert-DeclarativeActionToCommand {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Action
    )

    switch ([string]$Action.type) {
        'disableService' {
            $serviceName = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.name)
            return 'Stop-Service -Name {0} -Force; Set-Service -Name {0} -StartupType Disabled' -f $serviceName
        }
        'enableService' {
            $serviceName = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.name)
            $startupType = ConvertTo-PowerShellSingleQuotedString -Value ([string](Get-ObjectPropertyValue -InputObject $Action -Name 'startupType' -DefaultValue 'Manual'))
            return 'Set-Service -Name {0} -StartupType {1}; Start-Service -Name {0}' -f $serviceName, $startupType
        }
        'setRegistryDword' {
            $path = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.path)
            $name = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.name)
            $value = [int]$Action.value
            $command = 'New-Item -Path {0} -Force | Out-Null; New-ItemProperty -LiteralPath {0} -Name {1} -PropertyType DWord -Value {2} -Force | Out-Null' -f `
                $path,
                $name,
                $value

            if ([bool](Get-ObjectPropertyValue -InputObject $Action -Name 'bestEffort' -DefaultValue $false)) {
                $command = '{0} # optional best-effort' -f $command
            }

            if (Test-ActionRequiresAdministrator -Action $Action) {
                if ($command.EndsWith(' # optional best-effort', [StringComparison]::Ordinal)) {
                    return '{0}; run in elevated PowerShell' -f $command
                }

                return '{0} # run in elevated PowerShell' -f $command
            }

            return $command
        }
        'disableScheduledTask' {
            $taskPath = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.taskPath)
            $taskName = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.taskName)

            return 'Disable-ScheduledTask -TaskPath {0} -TaskName {1}' -f $taskPath, $taskName
        }
        'enableScheduledTask' {
            $taskPath = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.taskPath)
            $taskName = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.taskName)

            return 'Enable-ScheduledTask -TaskPath {0} -TaskName {1}' -f $taskPath, $taskName
        }
        'disableWer' {
            return 'Disable-WindowsErrorReporting'
        }
        'enableWer' {
            return 'Enable-WindowsErrorReporting'
        }
        'removeRegistryKey' {
            $path = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.path)
            return 'Remove-Item -LiteralPath {0} -Recurse -Force' -f $path
        }
        'removeRegistryValue' {
            $path = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.path)
            $name = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.name)
            return 'Remove-ItemProperty -LiteralPath {0} -Name {1} -Force -ErrorAction SilentlyContinue' -f $path, $name
        }
        'createRegistryKey' {
            $path = ConvertTo-PowerShellSingleQuotedString -Value ([string]$Action.path)
            return 'New-Item -Path {0} -Force | Out-Null' -f $path
        }
        'setMpPreference' {
            $name = [string]$Action.name
            $value = ConvertTo-PowerShellLiteral -Value $Action.value
            return 'Set-MpPreference -{0} {1}' -f $name, $value
        }
        default {
            return 'Unsupported action type: {0}' -f $Action.type
        }
    }
}

function Add-ChangeHistoryEntry {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Item,

        [Parameter(Mandatory = $true)]
        [object] $Action,

        [Parameter(Mandatory = $true)]
        [string] $BeforeState,

        [Parameter(Mandatory = $true)]
        [object] $Result
    )

    if ([string]::IsNullOrWhiteSpace($script:ChangeHistoryPath)) {
        return
    }

    try {
        $enableCommands = @(
            foreach ($enableAction in @($Item.enableActions)) {
                Convert-DeclarativeActionToCommand -Action $enableAction
            }
        )
        $entry = [PSCustomObject]@{
            timestamp        = (Get-Date -Format o)
            user             = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            computer         = $env:COMPUTERNAME
            itemId           = [string]$Item.id
            operationName    = [string]$Item.name
            scope            = [string]$Item.scope
            currentState     = $BeforeState
            operation        = Convert-DeclarativeActionToCommand -Action $Action
            actionType       = [string]$Action.type
            resultStatus     = [string]$Result.Status
            resultMessage    = [string]$Result.Message
            enableCommands   = $enableCommands
        }

        $entry |
            ConvertTo-Json -Depth 10 -Compress |
            Add-Content -LiteralPath $script:ChangeHistoryPath -Encoding UTF8
    }
    catch {
        Write-Host ('[WARN] Could not write change history: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

function Write-ExfiltrationLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter()]
        [string] $Prefix = '    '
    )

    $normalizedValue = $Value.Trim().ToLowerInvariant()

    switch ($normalizedValue) {
        'yes' {
            Write-Host ('{0}Exfiltration: Yes' -f $Prefix) -ForegroundColor Red
        }
        'possible' {
            Write-Host ('{0}Exfiltration: Possible' -f $Prefix) -ForegroundColor DarkYellow
        }
        'no' {
            Write-Host ('{0}Exfiltration: No' -f $Prefix) -ForegroundColor DarkGray
        }
        default {
            Write-Host ('{0}Exfiltration: Unknown' -f $Prefix) -ForegroundColor DarkGray
        }
    }
}

function Write-SeverityLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Value,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Reason = '',

        [Parameter()]
        [string] $Prefix = '    '
    )

    $normalizedValue = $Value.Trim().ToLowerInvariant()
    $label = 'Unknown'
    $color = Get-SeverityColor -Value $Value

    switch ($normalizedValue) {
        'urgent' {
            $label = 'Urgent'
        }
        'high' {
            $label = 'High'
        }
        'medium' {
            $label = 'Medium'
        }
        'low' {
            $label = 'Low'
        }
        'verylow' {
            $label = 'Very low'
        }
    }

    if ([string]::IsNullOrWhiteSpace($Reason)) {
        Write-Host ('{0}Severity:    {1}' -f $Prefix, $label) -ForegroundColor $color
        return
    }

    Write-Host ('{0}Severity:    {1} ({2})' -f $Prefix, $label, $Reason) -ForegroundColor $color
}

function Get-CurrentWindowsEditionFamily {
    try {
        $caption = ''
        $productName = ''
        $editionId = ''

        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $caption = [string]$os.Caption
        }
        catch {
        }

        try {
            $productName = [string](Get-ItemPropertyValue `
                -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                -Name 'ProductName' `
                -ErrorAction Stop)
        }
        catch {
        }

        try {
            $editionId = [string](Get-ItemPropertyValue `
                -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                -Name 'EditionID' `
                -ErrorAction Stop)
        }
        catch {
        }

        $text = ('{0} {1} {2}' -f $caption, $productName, $editionId)

        if ($text -match '(?i)server') {
            return 'Server'
        }
        if ($text -match '(?i)iot') {
            return 'IoT Enterprise'
        }
        if ($text -match '(?i)enterprise') {
            return 'Enterprise'
        }
        if ($text -match '(?i)education') {
            return 'Education'
        }
        if ($editionId -match '(?i)^core') {
            return 'Home'
        }
        if ($text -match '(?i)\bpro\b|professional') {
            return 'Pro'
        }
        if ($text -match '(?i)home') {
            return 'Home'
        }
    }
    catch {
    }

    return 'Unknown'
}

function Get-CurrentWindowsBuildNumber {
    try {
        $build = Get-ItemPropertyValue `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -Name 'CurrentBuildNumber' `
            -ErrorAction Stop

        return [int64]$build
    }
    catch {
    }

    try {
        $build = Get-ItemPropertyValue `
            -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
            -Name 'CurrentBuild' `
            -ErrorAction Stop

        return [int64]$build
    }
    catch {
    }

    return -1
}

function Get-OperatingSystemDisplayString {
    $caption = ''
    $architecture = ''
    $version = ''
    $build = ''

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = [string]$os.Caption
        $architecture = [string]$os.OSArchitecture
        $version = [string]$os.Version
        $build = [string]$os.BuildNumber
    }
    catch {
    }

    if ([string]::IsNullOrWhiteSpace($caption)) {
        try {
            $caption = [string](Get-ItemPropertyValue `
                -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                -Name 'ProductName' `
                -ErrorAction Stop)
        }
        catch {
        }
    }

    if ([string]::IsNullOrWhiteSpace($caption)) {
        $caption = 'Windows'
    }

    $caption = $caption -replace '^(?i)Microsoft\s+', ''

    if ([string]::IsNullOrWhiteSpace($architecture)) {
        if ([Environment]::Is64BitOperatingSystem) {
            $architecture = '64-bit'
        }
        else {
            $architecture = '32-bit'
        }
    }

    if ([string]::IsNullOrWhiteSpace($version)) {
        try {
            $majorMinor = [string](Get-ItemPropertyValue `
                -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                -Name 'CurrentMajorVersionNumber' `
                -ErrorAction Stop)
            $minor = [string](Get-ItemPropertyValue `
                -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                -Name 'CurrentMinorVersionNumber' `
                -ErrorAction Stop)
            $version = '{0}.{1}' -f $majorMinor, $minor
        }
        catch {
            $version = 'Unknown'
        }
    }
    else {
        $versionParts = @($version -split '\.')

        if ($versionParts.Count -ge 2) {
            $version = '{0}.{1}' -f $versionParts[0], $versionParts[1]
        }
    }

    if ([string]::IsNullOrWhiteSpace($build)) {
        $buildNumber = Get-CurrentWindowsBuildNumber

        if ($buildNumber -ge 0) {
            $build = [string]$buildNumber
        }
        else {
            $build = 'Unknown'
        }
    }

    $numericBuild = 0

    if ([int]::TryParse($build, [ref]$numericBuild) -and $numericBuild -ge 22000) {
        $caption = $caption -replace '(?i)^Windows 10\b', 'Windows 11'
    }

    return '{0} {1} ({2}, Build {3})' -f $caption, $architecture, $version, $build
}

function Test-EditionFamilyMatches {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $CurrentEdition,

        [Parameter(Mandatory = $true)]
        [string[]] $ApplicableEditions
    )

    if ($ApplicableEditions | Where-Object { $_ -match '(?i)^all($| )' }) {
        return $true
    }

    foreach ($edition in $ApplicableEditions) {
        if ($edition -eq $CurrentEdition) {
            return $true
        }
    }

    return $false
}

function Get-ItemApplicability {
    param(
        [Parameter(Mandatory = $true)]
        $Item
    )

    $applicableEditions = @(
        Get-ObjectPropertyValue `
            -InputObject $Item `
            -Name 'applicableWindowsEditions' `
            -DefaultValue @()
    )
    $applicableText = ($applicableEditions -join ', ')
    $note = [string](Get-ObjectPropertyValue -InputObject $Item -Name 'applicabilityNote' -DefaultValue '')

    if ([string]::IsNullOrWhiteSpace($applicableText)) {
        $applicableText = 'Unknown'
    }

    if (-not [string]::IsNullOrWhiteSpace($note)) {
        $applicableText = '{0}; {1}' -f $applicableText, $note
    }

    $currentEdition = Get-CurrentWindowsEditionFamily
    $currentBuild = Get-CurrentWindowsBuildNumber
    $minimumBuild = [int64](
        Get-ObjectPropertyValue `
            -InputObject $Item `
            -Name 'minimumWindowsBuild' `
            -DefaultValue 0
    )
    $buildSupported = $true

    if ($minimumBuild -gt 0 -and ($currentBuild -lt 0 -or $currentBuild -lt $minimumBuild)) {
        $buildSupported = $false
    }

    if ($currentEdition -eq 'Unknown') {
        return [PSCustomObject]@{
            Known          = $false
            IsApplicable   = $true
            BuildKnown     = ($currentBuild -ge 0)
            BuildSupported = $buildSupported
            CurrentBuild   = $currentBuild
            MinimumBuild   = $minimumBuild
            CurrentEdition = $currentEdition
            Details        = $applicableText
            Summary        = ('Unknown ({0})' -f $applicableText)
        }
    }

    $isApplicable = Test-EditionFamilyMatches `
        -CurrentEdition $currentEdition `
        -ApplicableEditions $applicableEditions

    $effectiveApplicable = ($isApplicable -and $buildSupported)

    $prefix = if ($effectiveApplicable) {
        'Yes'
    }
    else {
        'No'
    }

    return [PSCustomObject]@{
        Known          = $true
        IsApplicable   = $effectiveApplicable
        BuildKnown     = ($currentBuild -ge 0)
        BuildSupported = $buildSupported
        CurrentBuild   = $currentBuild
        MinimumBuild   = $minimumBuild
        CurrentEdition = $currentEdition
        Details        = $applicableText
        Summary        = $(if ($minimumBuild -gt 0) {
            ('{0} ({1}; current: {2}; build: {3}; minimum build: {4})' -f $prefix, $applicableText, $currentEdition, $currentBuild, $minimumBuild)
        }
        else {
            ('{0} ({1}; current: {2})' -f $prefix, $applicableText, $currentEdition)
        })
    }
}

function Write-ApplicabilityLine {
    param(
        [Parameter(Mandatory = $true)]
        $Item,

        [Parameter()]
        [string] $Prefix = '    '
    )

    $applicability = Get-ItemApplicability -Item $Item

    if (-not $applicability.Known) {
        Write-Host ('{0}isApplicable: {1}' -f $Prefix, $applicability.Summary) -ForegroundColor DarkYellow
        return
    }

    if ($applicability.IsApplicable) {
        Write-Host ('{0}isApplicable: {1}' -f $Prefix, $applicability.Summary) -ForegroundColor Green
        return
    }

    Write-Host ('{0}isApplicable: {1}' -f $Prefix, $applicability.Summary) -ForegroundColor DarkGray
}

function Get-SeverityColor {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Value
    )

    switch ($Value.Trim().ToLowerInvariant()) {
        'urgent' {
            return 'DarkRed'
        }
        'high' {
            return 'Red'
        }
        'medium' {
            return 'DarkYellow'
        }
        'low' {
            return 'DarkGreen'
        }
        'verylow' {
            return 'Green'
        }
        default {
            return 'DarkGray'
        }
    }
}

function Test-PolicyBackedItem {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Item
    )

    if ([string]$Item.id -match '^policy\.') {
        return $true
    }

    $paths = @()

    foreach ($check in @($Item.checks)) {
        if (Test-ObjectProperty -InputObject $check -Name 'path') {
            $paths += [string]$check.path
        }
    }

    foreach ($action in @($Item.disableActions)) {
        if (Test-ObjectProperty -InputObject $action -Name 'path') {
            $paths += [string]$action.path
        }
    }

    if ($paths.Count -eq 0) {
        return $false
    }

    $nonPolicyPaths = @(
        $paths |
            Where-Object {
                $_ -notmatch '(?i)^[A-Z]+:\\(?:SOFTWARE\\)?Policies\\' -and
                $_ -notmatch '(?i)^[A-Z]+:\\Software\\Policies\\'
            }
    )

    return ($nonPolicyPaths.Count -eq 0)
}

function Format-AuditItemTags {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Item
    )

    if (Test-PolicyBackedItem -Item $Item) {
        return '[policy] [{0}]' -f $Item.scope
    }

    return '[{0}]' -f $Item.scope
}

function Test-RegistryPolicyPath {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $Path
    )

    return (
        $Path -match '(?i)^[A-Z]+:\\(?:SOFTWARE\\)?Policies\\' -or
        $Path -match '(?i)^[A-Z]+:\\Software\\Policies\\'
    )
}

function Get-PolicyStateDisplayString {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Database
    )

    $policyItems = @(
        $Database.items |
            Where-Object {
                Test-PolicyBackedItem -Item $_
            }
    )
    $activePolicyItems = 0
    $activePolicyValues = 0

    foreach ($item in $policyItems) {
        $itemHasActivePolicyValue = $false

        foreach ($check in @($item.checks)) {
            if (
                [string]$check.type -ne 'registryDwordEquals' -or
                -not (Test-ObjectProperty -InputObject $check -Name 'path') -or
                -not (Test-ObjectProperty -InputObject $check -Name 'name') -or
                -not (Test-RegistryPolicyPath -Path ([string]$check.path))
            ) {
                continue
            }

            $state = Get-RegistryValueState `
                -Path ([string]$check.path) `
                -Name ([string]$check.name)

            if ($state.ValueExists) {
                $activePolicyValues++
                $itemHasActivePolicyValue = $true
            }
        }

        if ($itemHasActivePolicyValue) {
            $activePolicyItems++
        }
    }

    return '{0} value(s), {1}/{2} item(s) active' -f `
        $activePolicyValues,
        $activePolicyItems,
        $policyItems.Count
}

function Add-ValidationError {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]] $Errors,

        [Parameter(Mandatory = $true)]
        [string] $Message
    )

    $Errors.Add($Message)
}

function Test-DatabaseDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Database
    )

    $errors = New-Object 'System.Collections.Generic.List[string]'
    $supportedCheckTypes = @(
        'serviceDisabled',
        'registryDwordEquals',
        'scheduledTaskDisabled',
        'werDisabled',
        'registryKeyAbsent',
        'registryValueAbsent',
        'tailoredExperiencesDisabled',
        'mpPreferenceEquals'
    )
    $supportedActionTypes = @(
        'disableService',
        'enableService',
        'setRegistryDword',
        'disableScheduledTask',
        'enableScheduledTask',
        'disableWer',
        'enableWer',
        'removeRegistryKey',
        'removeRegistryValue',
        'createRegistryKey',
        'setMpPreference'
    )

    if (-not (Test-ObjectProperty -InputObject $Database -Name 'schemaVersion')) {
        Add-ValidationError -Errors $errors -Message 'Missing top-level property: schemaVersion.'
    }
    elseif ([int]$Database.schemaVersion -ne 1) {
        Add-ValidationError `
            -Errors $errors `
            -Message ('Unsupported schemaVersion: {0}. Expected 1.' -f $Database.schemaVersion)
    }

    if (-not (Test-ObjectProperty -InputObject $Database -Name 'items')) {
        Add-ValidationError -Errors $errors -Message 'Missing top-level property: items.'
        return $errors
    }

    $seenIds = @{}
    $itemIndex = 0

    foreach ($item in @($Database.items)) {
        $itemIndex++
        $context = 'items[{0}]' -f ($itemIndex - 1)

        foreach ($requiredProperty in @(
            'id',
            'name',
            'category',
            'scope',
            'description',
            'exfiltration',
            'severity',
            'severityReason',
            'applicableWindowsEditions',
            'applicabilityNote',
            'threatProofUrl',
            'threatProofExactQuote',
            'fixProofUrl',
            'fixProofExactQuote',
            'downsides',
            'checkCommands',
            'checks',
            'disableActions',
            'enableActions'
        )) {
            if (-not (Test-ObjectProperty -InputObject $item -Name $requiredProperty)) {
                Add-ValidationError `
                    -Errors $errors `
                    -Message ('{0}: missing property "{1}".' -f $context, $requiredProperty)
            }
        }

        if (-not (Test-ObjectProperty -InputObject $item -Name 'id')) {
            continue
        }

        $itemId = [string]$item.id

        if ($itemId -notmatch '^[a-z0-9][a-z0-9._-]*$') {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: id "{1}" must match ^[a-z0-9][a-z0-9._-]*$.' -f $context, $itemId)
        }

        if ($seenIds.ContainsKey($itemId)) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: duplicate id "{1}".' -f $context, $itemId)
        }
        else {
            $seenIds[$itemId] = $true
        }

        $scope = [string](Get-ObjectPropertyValue -InputObject $item -Name 'scope' -DefaultValue '')

        if ($scope -notin @('user', 'machine')) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: scope must be "user" or "machine".' -f $context)
        }

        $exfiltration = [string](Get-ObjectPropertyValue -InputObject $item -Name 'exfiltration' -DefaultValue '')

        if ($exfiltration -notin @('yes', 'possible', 'no')) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: exfiltration must be "yes", "possible", or "no".' -f $context)
        }

        $severity = [string](Get-ObjectPropertyValue -InputObject $item -Name 'severity' -DefaultValue '')

        if ($severity -notin @('urgent', 'high', 'medium', 'low', 'veryLow')) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: severity must be "urgent", "high", "medium", "low", or "veryLow".' -f $context)
        }

        $severityReason = [string](Get-ObjectPropertyValue -InputObject $item -Name 'severityReason' -DefaultValue '')

        if ([string]::IsNullOrWhiteSpace($severityReason)) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: severityReason must not be empty.' -f $context)
        }

        if (@(Get-ObjectPropertyValue -InputObject $item -Name 'applicableWindowsEditions' -DefaultValue @()).Count -eq 0) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: applicableWindowsEditions must contain at least one edition label.' -f $context)
        }

        foreach ($proofProperty in @(
            'threatProofUrl',
            'threatProofExactQuote',
            'fixProofUrl',
            'fixProofExactQuote'
        )) {
            $proofValue = [string](Get-ObjectPropertyValue -InputObject $item -Name $proofProperty -DefaultValue '')

            if ([string]::IsNullOrWhiteSpace($proofValue)) {
                Add-ValidationError `
                    -Errors $errors `
                    -Message ('{0}: {1} must not be empty.' -f $context, $proofProperty)
            }
        }

        if (@(Get-ObjectPropertyValue -InputObject $item -Name 'checkCommands' -DefaultValue @()).Count -eq 0) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: checkCommands must contain at least one command.' -f $context)
        }

        if (@(Get-ObjectPropertyValue -InputObject $item -Name 'checks' -DefaultValue @()).Count -eq 0) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: checks must contain at least one declarative check.' -f $context)
        }

        if (@(Get-ObjectPropertyValue -InputObject $item -Name 'disableActions' -DefaultValue @()).Count -eq 0) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: disableActions must contain at least one declarative action.' -f $context)
        }

        if (@(Get-ObjectPropertyValue -InputObject $item -Name 'enableActions' -DefaultValue @()).Count -eq 0) {
            Add-ValidationError `
                -Errors $errors `
                -Message ('{0}: enableActions must contain at least one declarative action.' -f $context)
        }

        $checkIndex = 0

        foreach ($check in @(Get-ObjectPropertyValue -InputObject $item -Name 'checks' -DefaultValue @())) {
            $checkContext = '{0}.checks[{1}]' -f $context, $checkIndex
            $checkIndex++

            if (-not (Test-ObjectProperty -InputObject $check -Name 'type')) {
                Add-ValidationError -Errors $errors -Message ('{0}: missing type.' -f $checkContext)
                continue
            }

            $checkType = [string]$check.type

            if ($checkType -notin $supportedCheckTypes) {
                Add-ValidationError `
                    -Errors $errors `
                    -Message ('{0}: unsupported check type "{1}".' -f $checkContext, $checkType)
                continue
            }

            switch ($checkType) {
                'serviceDisabled' {
                    if (-not (Test-ObjectProperty -InputObject $check -Name 'name')) {
                        Add-ValidationError -Errors $errors -Message ('{0}: missing name.' -f $checkContext)
                    }
                }
                'registryDwordEquals' {
                    foreach ($propertyName in @('path', 'name', 'value')) {
                        if (-not (Test-ObjectProperty -InputObject $check -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $checkContext, $propertyName)
                        }
                    }
                }
                'scheduledTaskDisabled' {
                    foreach ($propertyName in @('taskPath', 'taskName')) {
                        if (-not (Test-ObjectProperty -InputObject $check -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $checkContext, $propertyName)
                        }
                    }
                }
                'registryKeyAbsent' {
                    if (-not (Test-ObjectProperty -InputObject $check -Name 'path')) {
                        Add-ValidationError -Errors $errors -Message ('{0}: missing path.' -f $checkContext)
                    }
                }
                'registryValueAbsent' {
                    foreach ($propertyName in @('path', 'name')) {
                        if (-not (Test-ObjectProperty -InputObject $check -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $checkContext, $propertyName)
                        }
                    }
                }
                'tailoredExperiencesDisabled' {
                }
                'mpPreferenceEquals' {
                    foreach ($propertyName in @('name', 'value')) {
                        if (-not (Test-ObjectProperty -InputObject $check -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $checkContext, $propertyName)
                        }
                    }
                }
            }
        }

        $actionIndex = 0

        foreach ($action in @(
            @(Get-ObjectPropertyValue -InputObject $item -Name 'disableActions' -DefaultValue @()) +
            @(Get-ObjectPropertyValue -InputObject $item -Name 'enableActions' -DefaultValue @())
        )) {
            $actionContext = '{0}.actions[{1}]' -f $context, $actionIndex
            $actionIndex++

            if (-not (Test-ObjectProperty -InputObject $action -Name 'type')) {
                Add-ValidationError -Errors $errors -Message ('{0}: missing type.' -f $actionContext)
                continue
            }

            $actionType = [string]$action.type

            if ($actionType -notin $supportedActionTypes) {
                Add-ValidationError `
                    -Errors $errors `
                    -Message ('{0}: unsupported action type "{1}".' -f $actionContext, $actionType)
                continue
            }

            switch ($actionType) {
                'disableService' {
                    if (-not (Test-ObjectProperty -InputObject $action -Name 'name')) {
                        Add-ValidationError -Errors $errors -Message ('{0}: missing name.' -f $actionContext)
                    }
                }
                'enableService' {
                    if (-not (Test-ObjectProperty -InputObject $action -Name 'name')) {
                        Add-ValidationError -Errors $errors -Message ('{0}: missing name.' -f $actionContext)
                    }
                }
                'setRegistryDword' {
                    foreach ($propertyName in @('path', 'name', 'value')) {
                        if (-not (Test-ObjectProperty -InputObject $action -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $actionContext, $propertyName)
                        }
                    }
                }
                'disableScheduledTask' {
                    foreach ($propertyName in @('taskPath', 'taskName')) {
                        if (-not (Test-ObjectProperty -InputObject $action -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $actionContext, $propertyName)
                        }
                    }
                }
                'enableScheduledTask' {
                    foreach ($propertyName in @('taskPath', 'taskName')) {
                        if (-not (Test-ObjectProperty -InputObject $action -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $actionContext, $propertyName)
                        }
                    }
                }
                'removeRegistryKey' {
                    if (-not (Test-ObjectProperty -InputObject $action -Name 'path')) {
                        Add-ValidationError -Errors $errors -Message ('{0}: missing path.' -f $actionContext)
                    }
                }
                'removeRegistryValue' {
                    foreach ($propertyName in @('path', 'name')) {
                        if (-not (Test-ObjectProperty -InputObject $action -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $actionContext, $propertyName)
                        }
                    }
                }
                'createRegistryKey' {
                    if (-not (Test-ObjectProperty -InputObject $action -Name 'path')) {
                        Add-ValidationError -Errors $errors -Message ('{0}: missing path.' -f $actionContext)
                    }
                }
                'setMpPreference' {
                    foreach ($propertyName in @('name', 'value')) {
                        if (-not (Test-ObjectProperty -InputObject $action -Name $propertyName)) {
                            Add-ValidationError `
                                -Errors $errors `
                                -Message ('{0}: missing {1}.' -f $actionContext, $propertyName)
                        }
                    }
                }
            }
        }
    }

    return $errors
}

function Import-PrivacyDatabase {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $json = Get-Content -LiteralPath $resolvedPath -Raw -Encoding UTF8
    $database = $json | ConvertFrom-Json
    $validationErrors = @(Test-DatabaseDefinition -Database $database)

    if ($validationErrors.Count -gt 0) {
        $message = "Database validation failed:`n - " + ($validationErrors -join "`n - ")
        throw $message
    }

    return [PSCustomObject]@{
        Path     = $resolvedPath
        Database = $database
    }
}

function Get-RegistryValueState {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{
            PathExists  = $false
            ValueExists = $false
            Value       = $null
        }
    }

    $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    $property = $item.PSObject.Properties[$Name]

    if ($null -eq $property) {
        return [PSCustomObject]@{
            PathExists  = $true
            ValueExists = $false
            Value       = $null
        }
    }

    return [PSCustomObject]@{
        PathExists  = $true
        ValueExists = $true
        Value       = $property.Value
    }
}

function New-CheckResult {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [bool] $Compliant,

        [Parameter(Mandatory = $true)]
        [string] $Current,

        [Parameter()]
        [string] $ErrorMessage = '',

        [Parameter()]
        [bool] $Blocking = $true
    )

    return [PSCustomObject]@{
        Label        = $Label
        Compliant    = $Compliant
        Current      = $Current
        ErrorMessage = $ErrorMessage
        Blocking     = $Blocking
    }
}

function Test-DeclarativeCheck {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Check
    )

    try {
        switch ([string]$Check.type) {
            'serviceDisabled' {
                $serviceName = [string]$Check.name
                $escapedName = $serviceName.Replace("'", "''")
                $service = Get-CimInstance `
                    -ClassName Win32_Service `
                    -Filter ("Name='{0}'" -f $escapedName) `
                    -ErrorAction Stop

                if ($null -eq $service) {
                    return New-CheckResult `
                        -Label ("Service {0}" -f $serviceName) `
                        -Compliant $true `
                        -Current 'Not installed'
                }

                $compliant = (
                    $service.State -eq 'Stopped' -and
                    $service.StartMode -eq 'Disabled'
                )

                return New-CheckResult `
                    -Label ("Service {0}" -f $serviceName) `
                    -Compliant $compliant `
                    -Current ("State={0}; StartMode={1}" -f $service.State, $service.StartMode)
            }

            'registryDwordEquals' {
                $path = [string]$Check.path
                $name = [string]$Check.name
                $targetValue = [int64]$Check.value
                $missingIsIssue = [bool](
                    Get-ObjectPropertyValue `
                        -InputObject $Check `
                        -Name 'missingIsIssue' `
                        -DefaultValue $true
                )
                $blocking = [bool](
                    Get-ObjectPropertyValue `
                        -InputObject $Check `
                        -Name 'blocking' `
                        -DefaultValue $true
                )
                $state = Get-RegistryValueState -Path $path -Name $name

                if (-not $state.PathExists) {
                    return New-CheckResult `
                        -Label ("{0}\{1}" -f $path, $name) `
                        -Compliant (-not $missingIsIssue) `
                        -Current 'Registry path absent' `
                        -Blocking $blocking
                }

                if (-not $state.ValueExists) {
                    return New-CheckResult `
                        -Label ("{0}\{1}" -f $path, $name) `
                        -Compliant (-not $missingIsIssue) `
                        -Current 'Registry value absent' `
                        -Blocking $blocking
                }

                $currentValue = [int64]$state.Value

                return New-CheckResult `
                    -Label ("{0}\{1}" -f $path, $name) `
                    -Compliant ($currentValue -eq $targetValue) `
                    -Current ("Current={0}; Target={1}" -f $currentValue, $targetValue) `
                    -Blocking $blocking
            }

            'tailoredExperiencesDisabled' {
                $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
                $policyName = 'DisableTailoredExperiencesWithDiagnosticData'
                $userPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy'
                $userName = 'TailoredExperiencesWithDiagnosticDataEnabled'

                $policyState = Get-RegistryValueState -Path $policyPath -Name $policyName
                $userState = Get-RegistryValueState -Path $userPath -Name $userName

                $policySummary = if ($policyState.ValueExists) {
                    [string]$policyState.Value
                }
                elseif ($policyState.PathExists) {
                    'value absent'
                }
                else {
                    'absent'
                }

                $userSummary = if ($userState.ValueExists) {
                    [string]$userState.Value
                }
                elseif ($userState.PathExists) {
                    'value absent'
                }
                else {
                    'absent'
                }

                $policyDisables = $policyState.ValueExists -and ([int64]$policyState.Value -eq 1)
                $userDisables = $userState.ValueExists -and ([int64]$userState.Value -eq 0)
                $compliant = $policyDisables -or $userDisables
                $effectiveState = if ($compliant) {
                    'disabled for current user'
                }
                else {
                    'not explicitly disabled for current user'
                }

                return New-CheckResult `
                    -Label 'Tailored Experiences effective state' `
                    -Compliant $compliant `
                    -Current ('Machine policy: {0}; User setting: {1}; Effective state: {2}' -f `
                        $policySummary,
                        $userSummary,
                        $effectiveState)
            }

            'registryValueAbsent' {
                $path = [string]$Check.path
                $name = [string]$Check.name
                $state = Get-RegistryValueState -Path $path -Name $name

                if (-not $state.PathExists) {
                    return New-CheckResult `
                        -Label ("{0}\{1}" -f $path, $name) `
                        -Compliant $true `
                        -Current 'Registry path absent'
                }

                $current = if ($state.ValueExists) {
                    'Registry value present'
                }
                else {
                    'Registry value absent'
                }

                return New-CheckResult `
                    -Label ("{0}\{1}" -f $path, $name) `
                    -Compliant (-not $state.ValueExists) `
                    -Current $current
            }

            'mpPreferenceEquals' {
                $command = Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue

                if ($null -eq $command) {
                    return New-CheckResult `
                        -Label ([string]$Check.name) `
                        -Compliant $false `
                        -Current 'Get-MpPreference unavailable' `
                        -ErrorMessage 'Microsoft Defender PowerShell module is unavailable.'
                }

                $name = [string]$Check.name
                $preferences = Get-MpPreference -ErrorAction Stop
                $property = $preferences.PSObject.Properties[$name]

                if ($null -eq $property) {
                    return New-CheckResult `
                        -Label $name `
                        -Compliant $false `
                        -Current 'Preference absent' `
                        -ErrorMessage ('Get-MpPreference did not return property: {0}' -f $name)
                }

                $currentValue = $property.Value
                $targetValue = $Check.value
                $compliant = if ($targetValue -is [bool]) {
                    [bool]$currentValue -eq [bool]$targetValue
                }
                else {
                    [int64]$currentValue -eq [int64]$targetValue
                }

                return New-CheckResult `
                    -Label $name `
                    -Compliant $compliant `
                    -Current ('Current={0}; Target={1}' -f $currentValue, $targetValue)
            }

            'scheduledTaskDisabled' {
                $taskPath = [string]$Check.taskPath
                $taskName = [string]$Check.taskName
                $task = Get-ScheduledTask `
                    -TaskPath $taskPath `
                    -TaskName $taskName `
                    -ErrorAction SilentlyContinue

                if ($null -eq $task) {
                    return New-CheckResult `
                        -Label ("Task {0}{1}" -f $taskPath, $taskName) `
                        -Compliant $true `
                        -Current 'Not installed'
                }

                $enabled = [bool]$task.Settings.Enabled

                return New-CheckResult `
                    -Label ("Task {0}{1}" -f $taskPath, $taskName) `
                    -Compliant (-not $enabled) `
                    -Current ("State={0}; Enabled={1}" -f $task.State, $enabled)
            }

            'werDisabled' {
                $getWerCommand = Get-Command `
                    -Name 'Get-WindowsErrorReporting' `
                    -ErrorAction SilentlyContinue

                if ($null -ne $getWerCommand) {
                    $werState = Get-WindowsErrorReporting
                    $werText = [string]$werState
                    $disabled = (
                        $werState -eq $false -or
                        $werText -match '^(Disabled|False)$'
                    )

                    return New-CheckResult `
                        -Label 'Windows Error Reporting' `
                        -Compliant $disabled `
                        -Current $werText
                }

                $fallbackPath = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
                $fallbackState = Get-RegistryValueState `
                    -Path $fallbackPath `
                    -Name 'Disabled'

                if ($fallbackState.ValueExists) {
                    $disabled = ([int64]$fallbackState.Value -eq 1)

                    return New-CheckResult `
                        -Label 'Windows Error Reporting' `
                        -Compliant $disabled `
                        -Current ("Fallback registry Disabled={0}" -f $fallbackState.Value)
                }

                return New-CheckResult `
                    -Label 'Windows Error Reporting' `
                    -Compliant $false `
                    -Current 'Status command unavailable and Disabled policy absent' `
                    -ErrorMessage 'Could not determine WER status reliably.'
            }

            'registryKeyAbsent' {
                $path = [string]$Check.path
                $exists = Test-Path -LiteralPath $path

                return New-CheckResult `
                    -Label ("Registry key {0}" -f $path) `
                    -Compliant (-not $exists) `
                    -Current $(if ($exists) { 'Present' } else { 'Absent' })
            }

            default {
                return New-CheckResult `
                    -Label ([string]$Check.type) `
                    -Compliant $false `
                    -Current 'Unsupported check type' `
                    -ErrorMessage ('Unsupported check type: {0}' -f $Check.type)
            }
        }
    }
    catch {
        $label = if (Test-ObjectProperty -InputObject $Check -Name 'name') {
            [string]$Check.name
        }
        else {
            [string]$Check.type
        }

        return New-CheckResult `
            -Label $label `
            -Compliant $false `
            -Current 'Check failed' `
            -ErrorMessage $_.Exception.Message
    }
}

function Get-DefenderTamperProtectionState {
    $cached = Get-Variable `
        -Scope Script `
        -Name 'DefenderTamperProtectionStateCached' `
        -ErrorAction SilentlyContinue

    if ($null -ne $cached) {
        return $cached.Value
    }

    $state = [PSCustomObject]@{
        Known        = $false
        IsEnabled    = $false
        Summary      = 'Tamper Protection state is unknown'
        ErrorMessage = ''
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $value = $status.IsTamperProtected

        if ($null -ne $value) {
            $isEnabled = [bool]$value
            $state = [PSCustomObject]@{
                Known        = $true
                IsEnabled    = $isEnabled
                Summary      = ('Tamper Protection is {0}' -f $(if ($isEnabled) { 'enabled' } else { 'disabled' }))
                ErrorMessage = ''
            }
        }
    }
    catch {
        $state = [PSCustomObject]@{
            Known        = $false
            IsEnabled    = $false
            Summary      = 'Tamper Protection state is unknown'
            ErrorMessage = $_.Exception.Message
        }
    }

    if (-not $state.Known) {
        try {
            $registryValue = Get-ItemPropertyValue `
                -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' `
                -Name 'TamperProtection' `
                -ErrorAction Stop
            $isEnabled = ([int64]$registryValue -ne 0)
            $state = [PSCustomObject]@{
                Known        = $true
                IsEnabled    = $isEnabled
                Summary      = ('Tamper Protection is {0} (registry fallback)' -f $(if ($isEnabled) { 'enabled' } else { 'disabled' }))
                ErrorMessage = ''
            }
        }
        catch {
            $state = [PSCustomObject]@{
                Known        = $false
                IsEnabled    = $false
                Summary      = 'Tamper Protection state is unknown'
                ErrorMessage = $_.Exception.Message
            }
        }
    }

    $script:DefenderTamperProtectionStateCached = $state
    return $state
}

function Test-PrivacyItem {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Item
    )

    $applicability = Get-ItemApplicability -Item $Item
    $maybeOnUnsupportedEdition = [bool](
        Get-ObjectPropertyValue `
            -InputObject $Item `
            -Name 'maybeOnUnsupportedEdition' `
            -DefaultValue $false
    )
    $deprecatedAfterWindowsBuild = [int64](
        Get-ObjectPropertyValue `
            -InputObject $Item `
            -Name 'deprecatedAfterWindowsBuild' `
            -DefaultValue 0
    )

    if (
        $deprecatedAfterWindowsBuild -gt 0 -and
        $applicability.CurrentBuild -gt $deprecatedAfterWindowsBuild
    ) {
        return [PSCustomObject]@{
            Item                 = $Item
            Status               = 'Deprecated'
            CheckResults         = @()
            CurrentSummary       = ('Deprecated after Windows build {0}; current build: {1}. Skipped: {2}' -f $deprecatedAfterWindowsBuild, $applicability.CurrentBuild, $applicability.Summary)
            ErrorSummary         = ''
            ApplicabilitySummary = $applicability.Summary
            ManualReason         = ''
            MaybeReason          = ''
        }
    }

    if (
        $applicability.Known -and
        -not $applicability.IsApplicable -and
        (-not $maybeOnUnsupportedEdition -or -not $applicability.BuildSupported)
    ) {
        return [PSCustomObject]@{
            Item                 = $Item
            Status               = 'NotApplicable'
            CheckResults         = @()
            CurrentSummary       = ('Not applicable to this Windows edition: {0}' -f $applicability.Summary)
            ErrorSummary         = ''
            ApplicabilitySummary = $applicability.Summary
            ManualReason         = ''
            MaybeReason          = ''
        }
    }

    $checkResults = @()

    foreach ($check in @($Item.checks)) {
        $checkResults += Test-DeclarativeCheck -Check $check
    }

    $hasCheckError = @(
        $checkResults |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.ErrorMessage)
            }
    ).Count -gt 0

    $hasIssue = @(
        $checkResults |
            Where-Object {
                -not $_.Compliant -and
                $_.Blocking -and
                [string]::IsNullOrWhiteSpace($_.ErrorMessage)
            }
    ).Count -gt 0

    $status = if ($hasIssue) {
        'Issue'
    }
    elseif ($hasCheckError) {
        'Unknown'
    }
    else {
        'Compliant'
    }

    $currentSummary = (
        $checkResults |
            ForEach-Object {
                $suffix = if ($_.Blocking) {
                    ''
                }
                else {
                    ' (optional)'
                }

                '{0}: {1}{2}' -f $_.Label, $_.Current, $suffix
            }
    ) -join ' | '

    $errorSummary = (
        $checkResults |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.ErrorMessage)
            } |
            ForEach-Object {
                '{0}: {1}' -f $_.Label, $_.ErrorMessage
            }
    ) -join ' | '

    $manualReason = ''
    $maybeReason = ''

    if ($status -eq 'Issue' -and $applicability.Known -and -not $applicability.IsApplicable -and $maybeOnUnsupportedEdition) {
        $status = 'Maybe'
        $maybeReason = ('Official applicability says this item is not supported on the current Windows edition, but the registry-based fix can still theoretically be honored by the component: {0}' -f $applicability.Summary)
    }

    $manualWhenTamperProtected = [bool](
        Get-ObjectPropertyValue `
            -InputObject $Item `
            -Name 'manualWhenTamperProtected' `
            -DefaultValue $false
    )

    if ($status -eq 'Issue' -and $manualWhenTamperProtected) {
        $hasAbsentPolicyValue = @(
            $checkResults |
                Where-Object {
                    -not $_.Compliant -and
                    $_.Blocking -and
                    [string]::IsNullOrWhiteSpace($_.ErrorMessage) -and
                    $_.Current -match 'Registry (path|value) absent'
                }
        ).Count -gt 0

        if ($hasAbsentPolicyValue) {
            $tamperProtection = Get-DefenderTamperProtectionState

            if ($tamperProtection.Known -and $tamperProtection.IsEnabled) {
                $status = 'Manual'
                $manualReason = 'Tamper Protection is enabled; Windows can block or ignore this policy fix until Tamper Protection is turned off manually.'
            }
        }
    }

    return [PSCustomObject]@{
        Item                 = $Item
        Status               = $status
        CheckResults         = $checkResults
        CurrentSummary       = $currentSummary
        ErrorSummary         = $errorSummary
        ApplicabilitySummary = $applicability.Summary
        ManualReason         = $manualReason
        MaybeReason          = $maybeReason
    }
}

function Invoke-PrivacyAudit {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Database
    )

    Write-Section ('Windows Telemetry Audit - database {0}' -f $Database.databaseVersion)
    Write-Host ('Tool version: {0}' -f $script:ToolVersion) -ForegroundColor DarkGray
    Write-Host 'The audit phase is read-only. Database checkCommands are displayed, not executed.'
    Write-Host 'Typed checks in the engine determine status.'

    $results = @()
    $ignoredIds = @(Get-IgnoredIssueIds)

    foreach ($item in @($Database.items)) {
        $result = Test-PrivacyItem -Item $item
        $results += $result
        $itemTags = Format-AuditItemTags -Item $item

        switch ($result.Status) {
            'Compliant' {
                Write-Host ('[FIXED]  {0} {1}' -f $itemTags, $item.name) -ForegroundColor Green
            }
            'Issue' {
                if ([string]$item.id -in $ignoredIds) {
                    Write-Host ('[IGNORED] {0} {1}' -f $itemTags, $item.name) -ForegroundColor DarkGray
                    Write-Host ('          Current: {0}' -f $result.CurrentSummary) -ForegroundColor DarkGray
                }
                else {
                    Write-Host ('[ISSUE]  {0} {1}' -f $itemTags, $item.name) -ForegroundColor (Get-SeverityColor -Value ([string]$item.severity))
                    Write-Host ('          Current: {0}' -f $result.CurrentSummary)
                }
            }
            'Unknown' {
                Write-Host ('[UNKNOWN] {0} {1}' -f $itemTags, $item.name) -ForegroundColor Red
                Write-Host ('          Error: {0}' -f $result.ErrorSummary)
            }
            'Manual' {
                Write-Host ('[MANUAL] {0} {1}' -f $itemTags, $item.name) -ForegroundColor DarkYellow
                Write-Host ('          Current: {0}' -f $result.CurrentSummary)
                Write-Host ('          Manual: {0}' -f $result.ManualReason) -ForegroundColor DarkYellow
            }
            'Maybe' {
                Write-Host ('[MAYBE]  {0} {1}' -f $itemTags, $item.name) -ForegroundColor DarkYellow
                Write-Host ('          Current: {0}' -f $result.CurrentSummary)
                Write-Host ('          Maybe: {0}' -f $result.MaybeReason) -ForegroundColor DarkYellow
            }
            'NotApplicable' {
                Write-Host ('[SKIP]   {0} {1}' -f $itemTags, $item.name) -ForegroundColor DarkGray
                Write-Host ('          {0}' -f $result.CurrentSummary) -ForegroundColor DarkGray
            }
            'Deprecated' {
                Write-Host ('[DEPRECATED] {0} {1}' -f $itemTags, $item.name) -ForegroundColor DarkGray
                Write-Host ('             {0}' -f $result.CurrentSummary) -ForegroundColor DarkGray
            }
        }
    }

    $ignoredIssueResults = @(
        $results |
            Where-Object {
                $_.Status -eq 'Issue' -and
                [string]$_.Item.id -in $ignoredIds
            }
    )
    $issues = @()
    $issueNumber = 0
    $manualItems = @()
    $manualNumber = 0
    $maybeItems = @()
    $maybeNumber = 0

    foreach ($result in @(
        $results |
            Where-Object {
                $_.Status -eq 'Issue' -and
                [string]$_.Item.id -notin $ignoredIds
            }
    )) {
        $issueNumber++

        $issues += [PSCustomObject]@{
            Number = $issueNumber
            Result = $result
            Item   = $result.Item
        }
    }

    foreach ($result in @($results | Where-Object { $_.Status -eq 'Manual' })) {
        $manualNumber++

        $manualItems += [PSCustomObject]@{
            Number = $manualNumber
            Result = $result
            Item   = $result.Item
        }
    }

    foreach ($result in @($results | Where-Object { $_.Status -eq 'Maybe' })) {
        $maybeNumber++

        $maybeItems += [PSCustomObject]@{
            Number = $maybeNumber
            Result = $result
            Item   = $result.Item
        }
    }

    Write-Section 'Detected Privacy-Related Issues'
    Write-Host ''

    if ($issues.Count -eq 0 -and $maybeItems.Count -eq 0) {
        Write-Host 'No actionable issues were detected by the current database.' -ForegroundColor Green
    }
    else {
        foreach ($issue in $issues) {
            $item = $issue.Item
            $downsides = [string]$item.downsides

            if ([string]::IsNullOrWhiteSpace($downsides)) {
                $downsides = 'No known user-visible downside is documented in the database.'
            }

            Write-Host ('[{0}] {1}' -f $issue.Number, $item.name) -ForegroundColor (Get-SeverityColor -Value ([string]$item.severity))
            Write-Host ('    ID:          {0}' -f $item.id)
            Write-Host ('    Scope:       {0}' -f $item.scope)
            Write-Host ('    Category:    {0}' -f $item.category)
            Write-Host ('    Description: {0}' -f $item.description)
            Write-ApplicabilityLine -Item $item
            Write-Host ('    threatProofUrl:        {0}' -f $item.threatProofUrl) -ForegroundColor DarkGray
            Write-Host ('    threatProofExactQuote: {0}' -f $item.threatProofExactQuote) -ForegroundColor DarkGray
            Write-Host ('    Current:     {0}' -f $issue.Result.CurrentSummary)
            Write-ExfiltrationLine -Value ([string]$item.exfiltration)
            Write-SeverityLine -Value ([string]$item.severity) -Reason ([string]$item.severityReason)
            Write-Host ('    Downside:    {0}' -f $downsides) -ForegroundColor Yellow

            $fixCommands = @(
                foreach ($action in @($item.disableActions)) {
                    Convert-DeclarativeActionToCommand -Action $action
                }
            )

            for ($fixIndex = 0; $fixIndex -lt $fixCommands.Count; $fixIndex++) {
                if ($fixIndex -eq 0) {
                    Write-Host ('    Fix:         {0}' -f $fixCommands[$fixIndex]) -ForegroundColor Cyan
                }
                else {
                    Write-Host ('                 {0}' -f $fixCommands[$fixIndex]) -ForegroundColor Cyan
                }
            }

            Write-Host ('    fixProofUrl:           {0}' -f $item.fixProofUrl) -ForegroundColor DarkGray
            Write-Host ('    fixProofExactQuote:    {0}' -f $item.fixProofExactQuote) -ForegroundColor DarkGray

            $enableCommands = @(
                foreach ($action in @($item.enableActions)) {
                    Convert-DeclarativeActionToCommand -Action $action
                }
            )

            for ($enableIndex = 0; $enableIndex -lt $enableCommands.Count; $enableIndex++) {
                if ($enableIndex -eq 0) {
                    Write-Host ('    Enable:      {0}' -f $enableCommands[$enableIndex]) -ForegroundColor DarkGray
                }
                else {
                    Write-Host ('                 {0}' -f $enableCommands[$enableIndex]) -ForegroundColor DarkGray
                }
            }

            Write-Host ''
        }

        foreach ($maybe in $maybeItems) {
            $item = $maybe.Item
            $downsides = [string]$item.downsides

            if ([string]::IsNullOrWhiteSpace($downsides)) {
                $downsides = 'No known user-visible downside is documented in the database.'
            }

            Write-Host ('[M{0}] {1}' -f $maybe.Number, $item.name) -ForegroundColor DarkYellow
            Write-Host ('    ID:          {0}' -f $item.id)
            Write-Host ('    Scope:       {0}' -f $item.scope)
            Write-Host ('    Category:    {0}' -f $item.category)
            Write-Host ('    Description: {0}' -f $item.description)
            Write-ApplicabilityLine -Item $item
            Write-Host ('    Maybe:       {0}' -f $maybe.Result.MaybeReason) -ForegroundColor DarkYellow
            Write-Host ('    threatProofUrl:        {0}' -f $item.threatProofUrl) -ForegroundColor DarkGray
            Write-Host ('    threatProofExactQuote: {0}' -f $item.threatProofExactQuote) -ForegroundColor DarkGray
            Write-Host ('    Current:     {0}' -f $maybe.Result.CurrentSummary)
            Write-ExfiltrationLine -Value ([string]$item.exfiltration)
            Write-SeverityLine -Value ([string]$item.severity) -Reason ([string]$item.severityReason)
            Write-Host ('    Downside:    {0}' -f $downsides) -ForegroundColor Yellow

            $fixCommands = @(
                foreach ($action in @($item.disableActions)) {
                    Convert-DeclarativeActionToCommand -Action $action
                }
            )

            for ($fixIndex = 0; $fixIndex -lt $fixCommands.Count; $fixIndex++) {
                if ($fixIndex -eq 0) {
                    Write-Host ('    Fix:         {0}' -f $fixCommands[$fixIndex]) -ForegroundColor Cyan
                }
                else {
                    Write-Host ('                 {0}' -f $fixCommands[$fixIndex]) -ForegroundColor Cyan
                }
            }

            Write-Host ('    fixProofUrl:           {0}' -f $item.fixProofUrl) -ForegroundColor DarkGray
            Write-Host ('    fixProofExactQuote:    {0}' -f $item.fixProofExactQuote) -ForegroundColor DarkGray
            Write-Host ''
        }
    }

    if ($manualItems.Count -gt 0) {
        Write-Section 'Manual Privacy-Related Items'
        Write-Host ''

        foreach ($manual in $manualItems) {
            $item = $manual.Item
            $downsides = [string]$item.downsides

            if ([string]::IsNullOrWhiteSpace($downsides)) {
                $downsides = 'No known user-visible downside is documented in the database.'
            }

            Write-Host ('[M{0}] {1}' -f $manual.Number, $item.name) -ForegroundColor DarkYellow
            Write-Host ('    ID:          {0}' -f $item.id)
            Write-Host ('    Scope:       {0}' -f $item.scope)
            Write-Host ('    Category:    {0}' -f $item.category)
            Write-Host ('    Description: {0}' -f $item.description)
            Write-ApplicabilityLine -Item $item
            Write-Host ('    Current:     {0}' -f $manual.Result.CurrentSummary)
            Write-Host ('    Manual:      {0}' -f $manual.Result.ManualReason) -ForegroundColor DarkYellow
            Write-ExfiltrationLine -Value ([string]$item.exfiltration)
            Write-SeverityLine -Value ([string]$item.severity) -Reason ([string]$item.severityReason)
            Write-Host ('    Downside:    {0}' -f $downsides) -ForegroundColor Yellow
            Write-Host ''
        }
    }

    if ($ignoredIssueResults.Count -gt 0) {
        Write-Host ('Ignored: {0} detected issue(s) hidden from action list.' -f $ignoredIssueResults.Count) -ForegroundColor DarkGray
    }

    $unknownCount = @($results | Where-Object { $_.Status -eq 'Unknown' }).Count
    $notApplicableCount = @($results | Where-Object { $_.Status -eq 'NotApplicable' }).Count
    $deprecatedCount = @($results | Where-Object { $_.Status -eq 'Deprecated' }).Count
    $manualCount = @($results | Where-Object { $_.Status -eq 'Manual' }).Count
    $maybeCount = @($results | Where-Object { $_.Status -eq 'Maybe' }).Count

    Write-Host ('Summary: {0} issue(s), {1} maybe item(s), {2} manual item(s), {3} ignored issue(s), {4} unknown check(s), {5} compliant item(s), {6} not applicable item(s), {7} deprecated item(s).' -f `
        $issues.Count,
        $maybeCount,
        $manualCount,
        $ignoredIssueResults.Count,
        $unknownCount,
        @($results | Where-Object { $_.Status -eq 'Compliant' }).Count,
        $notApplicableCount,
        $deprecatedCount
    )

    return [PSCustomObject]@{
        Results       = $results
        Issues        = $issues
        MaybeItems    = $maybeItems
        ManualItems   = $manualItems
        IgnoredIssues = $ignoredIssueResults
    }
}

function Convert-SelectionTextToNumbers {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SelectionText,

        [Parameter(Mandatory = $true)]
        [int] $Maximum
    )

    $numbers = New-Object 'System.Collections.Generic.List[int]'

    foreach ($part in @($SelectionText -split ',')) {
        $token = $part.Trim()

        if ([string]::IsNullOrWhiteSpace($token)) {
            continue
        }

        if ($token -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]

            if ($start -gt $end) {
                throw ('Invalid descending range: {0}' -f $token)
            }

            foreach ($number in $start..$end) {
                if ($number -lt 1 -or $number -gt $Maximum) {
                    throw ('Selection {0} is outside 1..{1}.' -f $number, $Maximum)
                }

                if (-not $numbers.Contains($number)) {
                    $numbers.Add($number)
                }
            }

            continue
        }

        if ($token -notmatch '^\d+$') {
            throw ('Invalid selection token: "{0}".' -f $token)
        }

        $number = [int]$token

        if ($number -lt 1 -or $number -gt $Maximum) {
            throw ('Selection {0} is outside 1..{1}.' -f $number, $Maximum)
        }

        if (-not $numbers.Contains($number)) {
            $numbers.Add($number)
        }
    }

    return @($numbers | Sort-Object)
}

function Show-ItemDetails {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Issue
    )

    $item = $Issue.Item

    Write-Section ('Details: {0}' -f $item.name)
    Write-Host ('ID:          {0}' -f $item.id)
    Write-Host ('Scope:       {0}' -f $item.scope)
    Write-Host ('Category:    {0}' -f $item.category)
    Write-Host ('Description: {0}' -f $item.description)
    Write-ApplicabilityLine -Item $item -Prefix ''
    Write-Host ('threatProofUrl:        {0}' -f $item.threatProofUrl) -ForegroundColor DarkGray
    Write-Host ('threatProofExactQuote: {0}' -f $item.threatProofExactQuote) -ForegroundColor DarkGray
    Write-ExfiltrationLine -Value ([string]$item.exfiltration) -Prefix ''
    Write-SeverityLine -Value ([string]$item.severity) -Reason ([string]$item.severityReason) -Prefix ''

    $downsides = [string]$item.downsides

    if ([string]::IsNullOrWhiteSpace($downsides)) {
        $downsides = 'No known user-visible downside is documented in the database.'
    }

    Write-Host ('Downside:    {0}' -f $downsides) -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Human-readable status commands from the database:' -ForegroundColor Cyan

    foreach ($command in @($item.checkCommands)) {
        Write-Host ('  {0}' -f $command)
    }

    Write-Host ''
    Write-Host 'Human-readable fix commands from typed actions:' -ForegroundColor Cyan

    foreach ($action in @($item.disableActions)) {
        Write-Host ('  {0}' -f (Convert-DeclarativeActionToCommand -Action $action)) -ForegroundColor Cyan
    }

    Write-Host ''
    Write-Host ('fixProofUrl:        {0}' -f $item.fixProofUrl) -ForegroundColor DarkGray
    Write-Host ('fixProofExactQuote: {0}' -f $item.fixProofExactQuote) -ForegroundColor DarkGray

    Write-Host ''
    Write-Host 'Human-readable enable commands from typed actions:' -ForegroundColor Green

    foreach ($action in @($item.enableActions)) {
        Write-Host ('  {0}' -f (Convert-DeclarativeActionToCommand -Action $action)) -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host 'Important: those command strings are documentation only.'
    Write-Host 'The engine executes only whitelisted typed checks and actions.'
}

function Get-IgnoreListPath {
    if (-not [string]::IsNullOrWhiteSpace($script:IgnoreListPath)) {
        return $script:IgnoreListPath
    }

    $scriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $PSScriptRoot
    }
    else {
        (Get-Location).Path
    }

    $script:IgnoreListPath = Join-Path $scriptRoot 'ignored-issues.json'
    return $script:IgnoreListPath
}

function Read-IgnoredIssues {
    $path = Get-IgnoreListPath

    if (-not (Test-Path -LiteralPath $path)) {
        return @()
    }

    try {
        $content = Get-Content -LiteralPath $path -Raw -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($content)) {
            return @()
        }

        $parsed = ConvertFrom-Json -InputObject $content

        if ($null -eq $parsed) {
            return @()
        }

        return @($parsed)
    }
    catch {
        Write-Host ('[WARN] Could not read ignored issues: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
        return @()
    }
}

function Write-IgnoredIssues {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $IgnoredIssues
    )

    $path = Get-IgnoreListPath
    $directory = Split-Path -Parent $path

    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    @($IgnoredIssues) |
        ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $path -Encoding UTF8
}

function Get-IgnoredIssueIds {
    return @(
        Read-IgnoredIssues |
            ForEach-Object {
                [string]$_.itemId
            } |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }
    )
}

function Add-IgnoredIssues {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Issues
    )

    $existing = @(Read-IgnoredIssues)
    $byId = @{}

    foreach ($entry in $existing) {
        $itemId = [string]$entry.itemId

        if (-not [string]::IsNullOrWhiteSpace($itemId)) {
            $byId[$itemId] = $entry
        }
    }

    foreach ($issue in $Issues) {
        $item = $issue.Item
        $itemId = [string]$item.id

        $byId[$itemId] = [PSCustomObject]@{
            itemId       = $itemId
            name         = [string]$item.name
            scope        = [string]$item.scope
            ignoredAt    = (Get-Date -Format o)
            currentState = [string]$issue.Result.CurrentSummary
        }
    }

    Write-IgnoredIssues -IgnoredIssues @($byId.Values | Sort-Object itemId)
}

function Get-IgnoredIssueEntriesForAudit {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $AuditResults
    )

    $ignored = @(Read-IgnoredIssues)
    $entries = @()

    foreach ($ignoredEntry in $ignored) {
        $itemId = [string]$ignoredEntry.itemId
        $result = @(
            $AuditResults |
                Where-Object {
                    [string]$_.Item.id -eq $itemId
                }
        )

        $entries += [PSCustomObject]@{
            Entry  = $ignoredEntry
            Result = if ($result.Count -gt 0) { $result[0] } else { $null }
        }
    }

    return $entries
}

function Show-IgnoredIssues {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $AuditResults
    )

    Write-Section 'Ignored Issues'

    $entries = @(Get-IgnoredIssueEntriesForAudit -AuditResults $AuditResults)

    if ($entries.Count -eq 0) {
        Write-Host 'No ignored issues are configured.' -ForegroundColor Green
        return
    }

    $number = 0

    foreach ($entry in $entries) {
        $number++
        $ignoredEntry = $entry.Entry
        $result = $entry.Result
        $status = if ($null -ne $result) {
            [string]$result.Status
        }
        else {
            'Not in current database'
        }
        $current = if ($null -ne $result) {
            [string]$result.CurrentSummary
        }
        else {
            [string]$ignoredEntry.currentState
        }

        Write-Host ('[{0}] {1}' -f $number, $ignoredEntry.name) -ForegroundColor DarkGray
        Write-Host ('    ID:        {0}' -f $ignoredEntry.itemId)
        Write-Host ('    Scope:     {0}' -f $ignoredEntry.scope)
        Write-Host ('    IgnoredAt: {0}' -f $ignoredEntry.ignoredAt)
        Write-Host ('    Status:    {0}' -f $status)
        Write-Host ('    Current:   {0}' -f $current)
        Write-Host ''
    }
}

function Restore-IgnoredIssues {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SelectionText
    )

    $ignored = @(Read-IgnoredIssues)

    if ($ignored.Count -eq 0) {
        Write-Host 'No ignored issues are configured.' -ForegroundColor Yellow
        return
    }

    $numbers = @(
        Convert-SelectionTextToNumbers `
            -SelectionText $SelectionText `
            -Maximum $ignored.Count
    )
    $removeIds = @(
        for ($i = 0; $i -lt $ignored.Count; $i++) {
            if (($i + 1) -in $numbers) {
                [string]$ignored[$i].itemId
            }
        }
    )
    $remaining = @(
        $ignored |
            Where-Object {
                [string]$_.itemId -notin $removeIds
            }
    )

    Write-IgnoredIssues -IgnoredIssues $remaining
    Write-Host ('Restored {0} ignored issue(s).' -f $removeIds.Count) -ForegroundColor Green
}

function New-BackupDirectory {
    $commonDocuments = [Environment]::GetFolderPath('CommonDocuments')

    if ([string]::IsNullOrWhiteSpace($commonDocuments)) {
        $commonDocuments = $env:TEMP
    }

    $root = Join-Path $commonDocuments 'WindowsTelemetryRemoverBackups'
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $directory = Join-Path $root $timestamp

    New-Item -Path $directory -ItemType Directory -Force | Out-Null

    return $directory
}

function Convert-RegistryPathToNativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if ($Path.StartsWith('HKLM:\', [StringComparison]::OrdinalIgnoreCase)) {
        return 'HKEY_LOCAL_MACHINE\' + $Path.Substring(6)
    }

    if ($Path.StartsWith('HKCU:\', [StringComparison]::OrdinalIgnoreCase)) {
        return 'HKEY_CURRENT_USER\' + $Path.Substring(6)
    }

    throw ('Unsupported registry provider path: {0}' -f $Path)
}

function Save-PreChangeBackup {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Items,

        [Parameter(Mandatory = $true)]
        [object[]] $AuditResults,

        [Parameter(Mandatory = $true)]
        [string] $Directory
    )

    Write-Section 'Creating Backup'

    New-Item -Path $Directory -ItemType Directory -Force | Out-Null
    $script:LogPath = Join-Path $Directory 'operations.log'
    $script:ChangeHistoryPath = Join-Path $Directory 'change-history.jsonl'

    ('Backup created: {0}' -f (Get-Date -Format o)) |
        Set-Content -LiteralPath $script:LogPath -Encoding UTF8
    New-Item -Path $script:ChangeHistoryPath -ItemType File -Force | Out-Null

    try {
        $selectionSnapshot = [PSCustomObject]@{
            ToolVersion = $script:ToolVersion
            Computer    = $env:COMPUTERNAME
            User        = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            Timestamp   = (Get-Date -Format o)
            ItemIds     = @($Items | ForEach-Object { $_.id })
        }

        $selectionSnapshot |
            ConvertTo-Json -Depth 10 |
            Set-Content `
                -LiteralPath (Join-Path $Directory 'selection.json') `
                -Encoding UTF8

        Write-OperationResult -Status 'OK' -Message 'Saved selection.json.'
    }
    catch {
        Write-OperationResult -Status 'FAIL' -Message ('Could not save selection snapshot: {0}' -f $_.Exception.Message)
    }

    try {
        $selectedIds = @($Items | ForEach-Object { [string]$_.id })
        $beforeState = @(
            $AuditResults |
                Where-Object {
                    [string]$_.Item.id -in $selectedIds
                } |
                ForEach-Object {
                    [PSCustomObject]@{
                        Id             = $_.Item.id
                        Name           = $_.Item.name
                        Status         = $_.Status
                        CurrentSummary = $_.CurrentSummary
                        ErrorSummary   = $_.ErrorSummary
                    }
                }
        )

        $beforeState |
            ConvertTo-Json -Depth 10 |
            Set-Content `
                -LiteralPath (Join-Path $Directory 'before-state.json') `
                -Encoding UTF8

        Write-OperationResult -Status 'OK' -Message 'Saved before-state.json.'
    }
    catch {
        Write-OperationResult -Status 'FAIL' -Message ('Could not save pre-change state: {0}' -f $_.Exception.Message)
    }

    $actions = @()

    foreach ($item in $Items) {
        $actions += @($item.disableActions)
    }

    $serviceNames = @(
        $actions |
            Where-Object { $_.type -eq 'disableService' } |
            ForEach-Object { [string]$_.name } |
            Sort-Object -Unique
    )

    if ($serviceNames.Count -gt 0) {
        try {
            $services = @()

            foreach ($serviceName in $serviceNames) {
                $escapedName = $serviceName.Replace("'", "''")
                $service = Get-CimInstance `
                    -ClassName Win32_Service `
                    -Filter ("Name='{0}'" -f $escapedName) `
                    -ErrorAction SilentlyContinue

                if ($null -ne $service) {
                    $services += $service |
                        Select-Object Name, DisplayName, State, StartMode, PathName
                }
            }

            $services |
                Export-Csv `
                    -LiteralPath (Join-Path $Directory 'services-before.csv') `
                    -NoTypeInformation `
                    -Encoding UTF8

            Write-OperationResult -Status 'OK' -Message 'Saved services-before.csv.'
        }
        catch {
            Write-OperationResult -Status 'FAIL' -Message ('Could not save service backup: {0}' -f $_.Exception.Message)
        }
    }

    $registryPaths = @(
        $actions |
            Where-Object {
                $_.type -in @('setRegistryDword', 'removeRegistryKey')
            } |
            ForEach-Object {
                [string]$_.path
            } |
            Sort-Object -Unique
    )

    $registryIndex = 0

    foreach ($registryPath in $registryPaths) {
        $registryIndex++

        if (-not (Test-Path -LiteralPath $registryPath)) {
            Write-OperationResult `
                -Status 'SKIP' `
                -Message ('Registry backup skipped because path is absent: {0}' -f $registryPath)
            continue
        }

        try {
            $nativePath = Convert-RegistryPathToNativePath -Path $registryPath
            $backupFile = Join-Path $Directory ('registry-{0:D3}.reg' -f $registryIndex)

            & reg.exe export $nativePath $backupFile /y *> $null

            if ($LASTEXITCODE -eq 0) {
                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Exported registry key: {0}' -f $registryPath)
            }
            else {
                Write-OperationResult `
                    -Status 'FAIL' `
                    -Message ('reg.exe export failed for {0}; exit code {1}.' -f $registryPath, $LASTEXITCODE)
            }
        }
        catch {
            Write-OperationResult `
                -Status 'FAIL' `
                -Message ('Registry backup failed for {0}: {1}' -f $registryPath, $_.Exception.Message)
        }
    }

    $taskActions = @(
        $actions |
            Where-Object { $_.type -eq 'disableScheduledTask' }
    )

    if ($taskActions.Count -gt 0) {
        $taskDirectory = Join-Path $Directory 'scheduled-tasks'
        New-Item -Path $taskDirectory -ItemType Directory -Force | Out-Null
        $taskIndex = 0

        foreach ($action in $taskActions) {
            $taskIndex++

            try {
                $task = Get-ScheduledTask `
                    -TaskPath ([string]$action.taskPath) `
                    -TaskName ([string]$action.taskName) `
                    -ErrorAction SilentlyContinue

                if ($null -eq $task) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Task backup skipped because task is absent: {0}{1}' -f $action.taskPath, $action.taskName)
                    continue
                }

                $xml = Export-ScheduledTask `
                    -TaskPath ([string]$action.taskPath) `
                    -TaskName ([string]$action.taskName)

                $fileName = 'task-{0:D3}.xml' -f $taskIndex

                $xml |
                    Set-Content `
                        -LiteralPath (Join-Path $taskDirectory $fileName) `
                        -Encoding UTF8

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Exported scheduled task: {0}{1}' -f $action.taskPath, $action.taskName)
            }
            catch {
                Write-OperationResult `
                    -Status 'FAIL' `
                    -Message ('Task backup failed for {0}{1}: {2}' -f $action.taskPath, $action.taskName, $_.Exception.Message)
            }
        }
    }

    Write-Host ('Backup directory: {0}' -f $Directory) -ForegroundColor Cyan
}

function Invoke-DeclarativeAction {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Action
    )

    try {
        switch ([string]$Action.type) {
            'disableService' {
                $serviceName = [string]$Action.name
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

                if ($null -eq $service) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Service is not installed: {0}' -f $serviceName)
                    return
                }

                if ($service.Status -ne 'Stopped') {
                    Stop-Service `
                        -Name $serviceName `
                        -Force `
                        -ErrorAction Stop
                }

                Set-Service `
                    -Name $serviceName `
                    -StartupType Disabled `
                    -ErrorAction Stop

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Stopped and disabled service: {0}' -f $serviceName)
                return
            }

            'enableService' {
                $serviceName = [string]$Action.name
                $startupType = [string](Get-ObjectPropertyValue -InputObject $Action -Name 'startupType' -DefaultValue 'Manual')
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

                if ($null -eq $service) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Service is not installed: {0}' -f $serviceName)
                    return
                }

                Set-Service `
                    -Name $serviceName `
                    -StartupType $startupType `
                    -ErrorAction Stop

                Start-Service `
                    -Name $serviceName `
                    -ErrorAction Stop

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Enabled service: {0}; StartupType={1}' -f $serviceName, $startupType)
                return
            }

            'setRegistryDword' {
                $path = [string]$Action.path
                $name = [string]$Action.name
                $value = [int]$Action.value

                if (-not (Test-Path -LiteralPath $path)) {
                    New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                }

                New-ItemProperty `
                    -LiteralPath $path `
                    -Name $name `
                    -PropertyType DWord `
                    -Value $value `
                    -Force `
                    -ErrorAction Stop |
                    Out-Null

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Set registry DWORD: {0}\{1}={2}' -f $path, $name, $value)
                return
            }

            'disableScheduledTask' {
                $taskPath = [string]$Action.taskPath
                $taskName = [string]$Action.taskName
                $task = Get-ScheduledTask `
                    -TaskPath $taskPath `
                    -TaskName $taskName `
                    -ErrorAction SilentlyContinue

                if ($null -eq $task) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Scheduled task is absent: {0}{1}' -f $taskPath, $taskName)
                    return
                }

                if (-not [bool]$task.Settings.Enabled) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Scheduled task is already disabled: {0}{1}' -f $taskPath, $taskName)
                    return
                }

                Disable-ScheduledTask `
                    -TaskPath $taskPath `
                    -TaskName $taskName `
                    -ErrorAction Stop |
                    Out-Null

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Disabled scheduled task: {0}{1}' -f $taskPath, $taskName)
                return
            }

            'enableScheduledTask' {
                $taskPath = [string]$Action.taskPath
                $taskName = [string]$Action.taskName
                $task = Get-ScheduledTask `
                    -TaskPath $taskPath `
                    -TaskName $taskName `
                    -ErrorAction SilentlyContinue

                if ($null -eq $task) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Scheduled task is absent: {0}{1}' -f $taskPath, $taskName)
                    return
                }

                Enable-ScheduledTask `
                    -TaskPath $taskPath `
                    -TaskName $taskName `
                    -ErrorAction Stop |
                    Out-Null

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Enabled scheduled task: {0}{1}' -f $taskPath, $taskName)
                return
            }

            'disableWer' {
                $command = Get-Command `
                    -Name 'Disable-WindowsErrorReporting' `
                    -ErrorAction SilentlyContinue

                if ($null -eq $command) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message 'Disable-WindowsErrorReporting is unavailable; registry fallback actions may still apply.'
                    return
                }

                $result = Disable-WindowsErrorReporting

                if ($result -eq $false) {
                    Write-OperationResult `
                        -Status 'FAIL' `
                        -Message 'Disable-WindowsErrorReporting returned False.'
                    return
                }

                Write-OperationResult `
                    -Status 'OK' `
                    -Message 'Disabled Windows Error Reporting.'
                return
            }

            'enableWer' {
                $command = Get-Command `
                    -Name 'Enable-WindowsErrorReporting' `
                    -ErrorAction SilentlyContinue

                if ($null -eq $command) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message 'Enable-WindowsErrorReporting is unavailable; registry fallback actions may still apply.'
                    return
                }

                $result = Enable-WindowsErrorReporting

                if ($result -eq $false) {
                    Write-OperationResult `
                        -Status 'FAIL' `
                        -Message 'Enable-WindowsErrorReporting returned False.'
                    return
                }

                Write-OperationResult `
                    -Status 'OK' `
                    -Message 'Enabled Windows Error Reporting.'
                return
            }

            'removeRegistryKey' {
                $path = [string]$Action.path

                if (-not (Test-Path -LiteralPath $path)) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Registry key is already absent: {0}' -f $path)
                    return
                }

                Remove-Item `
                    -LiteralPath $path `
                    -Recurse `
                    -Force `
                    -ErrorAction Stop

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Removed registry key: {0}' -f $path)
                return
            }

            'removeRegistryValue' {
                $path = [string]$Action.path
                $name = [string]$Action.name

                if (-not (Test-Path -LiteralPath $path)) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Registry path is absent: {0}' -f $path)
                    return
                }

                $state = Get-RegistryValueState -Path $path -Name $name

                if (-not $state.ValueExists) {
                    Write-OperationResult `
                        -Status 'SKIP' `
                        -Message ('Registry value is already absent: {0}\{1}' -f $path, $name)
                    return
                }

                Remove-ItemProperty `
                    -LiteralPath $path `
                    -Name $name `
                    -Force `
                    -ErrorAction Stop

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Removed registry value: {0}\{1}' -f $path, $name)
                return
            }

            'createRegistryKey' {
                $path = [string]$Action.path

                New-Item `
                    -Path $path `
                    -Force `
                    -ErrorAction Stop |
                    Out-Null

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Created registry key: {0}' -f $path)
                return
            }

            'setMpPreference' {
                $command = Get-Command -Name 'Set-MpPreference' -ErrorAction SilentlyContinue

                if ($null -eq $command) {
                    Write-OperationResult `
                        -Status 'FAIL' `
                        -Message 'Set-MpPreference is unavailable.'
                    return
                }

                $name = [string]$Action.name
                $parameters = @{}
                $parameters[$name] = $Action.value

                Set-MpPreference @parameters -ErrorAction Stop

                Write-OperationResult `
                    -Status 'OK' `
                    -Message ('Set Microsoft Defender preference: {0}={1}' -f $name, $Action.value)
                return
            }

            default {
                Write-OperationResult `
                    -Status 'FAIL' `
                    -Message ('Unsupported action type: {0}' -f $Action.type)
                return
            }
        }
    }
    catch {
        $bestEffort = [bool](
            Get-ObjectPropertyValue `
                -InputObject $Action `
                -Name 'bestEffort' `
                -DefaultValue $false
        )

        if ($bestEffort) {
            Write-OperationResult `
                -Status 'SKIP' `
                -Message ('Optional action {0} could not be applied: {1}' -f $Action.type, $_.Exception.Message)
            return
        }

        Write-OperationResult `
            -Status 'FAIL' `
            -Message ('Action {0} failed: {1}' -f $Action.type, $_.Exception.Message)
    }
}

function Invoke-ItemActions {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Items
    )

    foreach ($item in $Items) {
        Write-Section ('Applying: {0}' -f $item.name)
        $beforeState = (Test-PrivacyItem -Item $item).CurrentSummary

        foreach ($action in @($item.disableActions)) {
            $script:LastOperationResult = $null
            Invoke-DeclarativeAction -Action $action

            if ($null -ne $script:LastOperationResult) {
                Add-ChangeHistoryEntry `
                    -Item $item `
                    -Action $action `
                    -BeforeState $beforeState `
                    -Result $script:LastOperationResult
            }
        }

        $verification = Test-PrivacyItem -Item $item

        if ($verification.Status -eq 'Compliant') {
            Write-OperationResult `
                -Status 'OK' `
                -Message ('Verification passed: {0}' -f $item.name)
        }
        elseif ($verification.Status -eq 'Unknown') {
            Write-OperationResult `
                -Status 'FAIL' `
                -Message ('Verification was inconclusive for {0}: {1}' -f $item.name, $verification.ErrorSummary)
        }
        else {
            Write-OperationResult `
                -Status 'FAIL' `
                -Message ('Verification still reports an issue for {0}: {1}' -f $item.name, $verification.CurrentSummary)
        }
    }
}

function Get-ItemsByIds {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Database,

        [Parameter(Mandatory = $true)]
        [string[]] $Ids
    )

    $items = @()

    foreach ($id in $Ids) {
        $matchingItems = @(
            $Database.items |
                Where-Object {
                    [string]$_.id -eq $id
                }
        )

        if ($matchingItems.Count -ne 1) {
            throw ('Database item was not found exactly once: {0}' -f $id)
        }

        $items += $matchingItems[0]
    }

    return $items
}

function Test-ActionRequiresAdministrator {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Action
    )

    $explicitValue = Get-ObjectPropertyValue `
        -InputObject $Action `
        -Name 'requiresAdministrator' `
        -DefaultValue $null

    if ($null -ne $explicitValue) {
        return [bool]$explicitValue
    }

    if ([string]$Action.type -eq 'setRegistryDword') {
        $path = [string]$Action.path

        return $path.StartsWith('HKCU:\Software\Policies\', [StringComparison]::OrdinalIgnoreCase)
    }

    if ([string]$Action.type -eq 'setMpPreference') {
        return $true
    }

    return $false
}

function Test-ItemRequiresAdministrator {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Item
    )

    if ([string]$Item.scope -eq 'machine') {
        return $true
    }

    foreach ($action in @($Item.disableActions)) {
        if (Test-ActionRequiresAdministrator -Action $action) {
            return $true
        }
    }

    return $false
}

function Start-ElevatedActions {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Items,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedDatabasePath,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedBackupDirectory,

        [Parameter(Mandatory = $true)]
        [string] $Reason
    )

    $ids = @($Items | ForEach-Object { [string]$_.id })
    $idArgument = $ids -join ','

    if ($idArgument -notmatch '^[a-z0-9._,-]+$') {
        throw 'The generated ID argument contains unexpected characters.'
    }

    $powershellPath = Join-Path $PSHOME 'powershell.exe'
    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        ('"{0}"' -f $PSCommandPath),
        '-DatabasePath',
        ('"{0}"' -f $ResolvedDatabasePath),
        '-ApplyIds',
        ('"{0}"' -f $idArgument),
        '-BackupDirectory',
        ('"{0}"' -f $ResolvedBackupDirectory),
        '-NonInteractive'
    )

    Write-Host ''
    Write-Host ('Requesting administrator privileges for {0}...' -f $Reason) -ForegroundColor Yellow
    Write-Host 'If Windows asks for a different admin account, cancel; HKCU settings must be applied as this same user.' -ForegroundColor Yellow

    $process = Start-Process `
        -FilePath $powershellPath `
        -ArgumentList $arguments `
        -Verb RunAs `
        -Wait `
        -PassThru `
        -ErrorAction Stop

    if ($process.ExitCode -ne 0) {
        Write-OperationResult `
            -Status 'FAIL' `
            -Message ('Elevated process returned exit code {0}.' -f $process.ExitCode)
    }
    else {
        Write-OperationResult `
            -Status 'OK' `
            -Message ('Elevated actions completed: {0}.' -f $Reason)
    }
}

function Invoke-SelectedItems {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Items,

        [Parameter(Mandatory = $true)]
        [object] $Database,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedDatabasePath,

        [Parameter(Mandatory = $true)]
        [object[]] $AuditResults
    )

    if ($Items.Count -eq 0) {
        Write-Host 'No items selected.' -ForegroundColor Yellow
        return
    }

    $directory = New-BackupDirectory
    Save-PreChangeBackup `
        -Items $Items `
        -AuditResults $AuditResults `
        -Directory $directory

    $userItems = @(
        $Items |
            Where-Object {
                $_.scope -eq 'user' -and
                -not (Test-ItemRequiresAdministrator -Item $_)
            }
    )
    $elevatedUserItems = @(
        $Items |
            Where-Object {
                $_.scope -eq 'user' -and
                (Test-ItemRequiresAdministrator -Item $_)
            }
    )
    $machineItems = @($Items | Where-Object { $_.scope -eq 'machine' })

    if ($userItems.Count -gt 0) {
        Write-Section 'Applying Current-User Actions'
        Invoke-ItemActions -Items $userItems
    }

    if ($elevatedUserItems.Count -gt 0) {
        if (Test-IsAdministrator) {
            Write-Section 'Applying Current-User Policy Actions'
            Invoke-ItemActions -Items $elevatedUserItems
        }
        else {
            try {
                Start-ElevatedActions `
                    -Items $elevatedUserItems `
                    -ResolvedDatabasePath $ResolvedDatabasePath `
                    -ResolvedBackupDirectory $directory `
                    -Reason 'current-user policy-backed items'
            }
            catch {
                Write-OperationResult `
                    -Status 'FAIL' `
                    -Message ('Administrator elevation failed or was cancelled for current-user policy-backed items: {0}' -f $_.Exception.Message)
            }
        }
    }

    if ($machineItems.Count -gt 0) {
        if (Test-IsAdministrator) {
            Write-Section 'Applying Machine-Wide Actions'
            Invoke-ItemActions -Items $machineItems
        }
        else {
            try {
                Start-ElevatedActions `
                    -Items $machineItems `
                    -ResolvedDatabasePath $ResolvedDatabasePath `
                    -ResolvedBackupDirectory $directory `
                    -Reason 'machine-wide items'
            }
            catch {
                Write-OperationResult `
                    -Status 'FAIL' `
                    -Message ('Administrator elevation failed or was cancelled: {0}' -f $_.Exception.Message)
            }
        }
    }

    Write-Host ''
    Write-Host ('Backup and logs: {0}' -f $directory) -ForegroundColor Cyan
}

function Confirm-Selection {
    param(
        [Parameter(Mandatory = $true)]
        [object[]] $Items,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedText
    )

    Write-Section 'Selected Changes'

    foreach ($item in $Items) {
        $downsides = [string]$item.downsides

        if ([string]::IsNullOrWhiteSpace($downsides)) {
            $downsides = 'No known user-visible downside is documented.'
        }

        Write-Host ('- [{0}] {1}' -f $item.scope, $item.name) -ForegroundColor Yellow
        Write-Host ('  Possible downside: {0}' -f $downsides)
    }

    Write-Host ''
    $confirmation = Read-Host ('Type {0} to continue' -f $ExpectedText)

    return $confirmation -ceq $ExpectedText
}

function Invoke-InteractiveMenu {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Database,

        [Parameter(Mandatory = $true)]
        [string] $ResolvedDatabasePath
    )

    while ($true) {
        $audit = Invoke-PrivacyAudit -Database $Database

        Write-Section 'Actions Menu'

        if ($audit.Issues.Count -gt 0) {
            Write-Host '[1] Manually select detected issue numbers to fix'
            Write-Host '[2] Fix all detected issues'
            Write-Host '[3] Show details and check commands for one detected issue'
        }
        else {
            Write-Host 'No detected issues are available for fixing.' -ForegroundColor Green
        }

        Write-Host '[4] Run the audit again'
        if ($audit.Issues.Count -gt 0) {
            Write-Host '[5] Manually select detected issue to ignore'
        }
        Write-Host '[6] Show ignored issues'
        Write-Host '[7] Restore ignored issue'
        Write-Host '[0] Exit'
        Write-Host ''

        $choice = Read-Host 'Select an option'

        switch ($choice) {
            '1' {
                if ($audit.Issues.Count -eq 0) {
                    Write-Host 'There are no detected issues to select.' -ForegroundColor Yellow
                    continue
                }

                $selectionText = Read-Host 'Enter numbers and ranges, for example: 1,3,5-7'

                try {
                    $numbers = @(
                        Convert-SelectionTextToNumbers `
                            -SelectionText $selectionText `
                            -Maximum $audit.Issues.Count
                    )

                    $selectedIssues = @(
                        $audit.Issues |
                            Where-Object {
                                $_.Number -in $numbers
                            }
                    )
                    $selectedItems = @(
                        $selectedIssues |
                            ForEach-Object {
                                $_.Item
                            }
                    )

                    if (-not (Confirm-Selection -Items $selectedItems -ExpectedText 'YES')) {
                        Write-Host 'Cancelled. No changes were made.' -ForegroundColor Yellow
                        continue
                    }

                    Invoke-SelectedItems `
                        -Items $selectedItems `
                        -Database $Database `
                        -ResolvedDatabasePath $ResolvedDatabasePath `
                        -AuditResults $audit.Results
                }
                catch {
                    Write-Host ('Selection failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
                }
            }

            '2' {
                if ($audit.Issues.Count -eq 0) {
                    Write-Host 'There are no detected issues to fix.' -ForegroundColor Yellow
                    continue
                }

                $selectedItems = @(
                    $audit.Issues |
                        ForEach-Object {
                            $_.Item
                        }
                )

                if (-not (Confirm-Selection -Items $selectedItems -ExpectedText 'DISABLE ALL')) {
                    Write-Host 'Cancelled. No changes were made.' -ForegroundColor Yellow
                    continue
                }

                Invoke-SelectedItems `
                    -Items $selectedItems `
                    -Database $Database `
                    -ResolvedDatabasePath $ResolvedDatabasePath `
                    -AuditResults $audit.Results
            }

            '3' {
                if ($audit.Issues.Count -eq 0) {
                    Write-Host 'There are no detected issues to inspect.' -ForegroundColor Yellow
                    continue
                }

                $detailText = Read-Host ('Enter an issue number from 1 to {0}' -f $audit.Issues.Count)

                if ($detailText -notmatch '^\d+$') {
                    Write-Host 'Invalid issue number.' -ForegroundColor Red
                    continue
                }

                $detailNumber = [int]$detailText
                $issue = @(
                    $audit.Issues |
                        Where-Object {
                            $_.Number -eq $detailNumber
                        }
                )

                if ($issue.Count -ne 1) {
                    Write-Host 'Issue number was not found.' -ForegroundColor Red
                    continue
                }

                Show-ItemDetails -Issue $issue[0]
                [void](Read-Host 'Press Enter to return to the menu')
            }

            '4' {
                continue
            }

            '5' {
                if ($audit.Issues.Count -eq 0) {
                    Write-Host 'There are no detected issues to ignore.' -ForegroundColor Yellow
                    continue
                }

                $selectionText = Read-Host 'Enter issue numbers and ranges to ignore, for example: 1,3,5-7'

                try {
                    $numbers = @(
                        Convert-SelectionTextToNumbers `
                            -SelectionText $selectionText `
                            -Maximum $audit.Issues.Count
                    )
                    $selectedIssues = @(
                        $audit.Issues |
                            Where-Object {
                                $_.Number -in $numbers
                            }
                    )

                    if ($selectedIssues.Count -eq 0) {
                        Write-Host 'No issues were selected.' -ForegroundColor Yellow
                        continue
                    }

                    Add-IgnoredIssues -Issues $selectedIssues
                    Write-Host ('Ignored {0} issue(s). Run the audit again to hide them from the action list.' -f $selectedIssues.Count) -ForegroundColor Green
                }
                catch {
                    Write-Host ('Ignore failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
                }
            }

            '6' {
                Show-IgnoredIssues -AuditResults $audit.Results
                [void](Read-Host 'Press Enter to return to the menu')
            }

            '7' {
                Show-IgnoredIssues -AuditResults $audit.Results
                $ignored = @(Read-IgnoredIssues)

                if ($ignored.Count -eq 0) {
                    [void](Read-Host 'Press Enter to return to the menu')
                    continue
                }

                $selectionText = Read-Host ('Enter ignored issue numbers to restore from 1 to {0}' -f $ignored.Count)

                try {
                    Restore-IgnoredIssues -SelectionText $selectionText
                }
                catch {
                    Write-Host ('Restore failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
                }

                [void](Read-Host 'Press Enter to return to the menu')
            }

            '0' {
                return
            }

            default {
                Write-Host 'Unknown menu option.' -ForegroundColor Red
            }
        }
    }
}

try {
    $importedDatabase = Import-PrivacyDatabase -Path $DatabasePath
    $database = $importedDatabase.Database
    $resolvedDatabasePath = $importedDatabase.Path

    Write-Host ('Windows Telemetry Remover {0}' -f $script:ToolVersion) -ForegroundColor Green
    Write-Host ('Operating System: {0}' -f (Get-OperatingSystemDisplayString))
    Write-Host ('Policy Registry: {0}' -f (Get-PolicyStateDisplayString -Database $database))
    Write-Host ('Database: {0}' -f $resolvedDatabasePath)
    Write-Host ('Database version: {0}' -f $database.databaseVersion)

    if ($ValidateOnly) {
        Write-Host ('Database is valid. Loaded {0} item(s).' -f @($database.items).Count) -ForegroundColor Green
        exit 0
    }

    if (-not [string]::IsNullOrWhiteSpace($ApplyIds)) {
        $ids = @(
            $ApplyIds -split ',' |
                ForEach-Object {
                    $_.Trim()
                } |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
        )

        if ($ids.Count -eq 0) {
            throw 'ApplyIds did not contain any IDs.'
        }

        $items = @(Get-ItemsByIds -Database $database -Ids $ids)
        $administratorItems = @(
            $items |
                Where-Object {
                    Test-ItemRequiresAdministrator -Item $_
                }
        )

        if ($administratorItems.Count -gt 0 -and -not (Test-IsAdministrator)) {
            throw 'One or more selected actions require an elevated administrator process.'
        }

        if ([string]::IsNullOrWhiteSpace($BackupDirectory)) {
            $BackupDirectory = New-BackupDirectory
        }

        New-Item -Path $BackupDirectory -ItemType Directory -Force | Out-Null
        $script:LogPath = Join-Path $BackupDirectory 'operations.log'
        $script:ChangeHistoryPath = Join-Path $BackupDirectory 'change-history.jsonl'

        if (-not (Test-Path -LiteralPath $script:ChangeHistoryPath)) {
            New-Item -Path $script:ChangeHistoryPath -ItemType File -Force | Out-Null
        }

        Invoke-ItemActions -Items $items

        if ($script:OperationFailures -gt 0) {
            exit 1
        }

        exit 0
    }

    if ($AuditOnly) {
        [void](Invoke-PrivacyAudit -Database $database)
        exit 0
    }

    if ($NonInteractive) {
        throw 'NonInteractive was specified without ApplyIds.'
    }

    Invoke-InteractiveMenu `
        -Database $database `
        -ResolvedDatabasePath $resolvedDatabasePath

    exit 0
}
catch {
    Write-Host ''
    Write-Host ('[FATAL] {0}' -f $_.Exception.Message) -ForegroundColor Red

    if (-not $NonInteractive) {
        [void](Read-Host 'Press Enter to close')
    }

    exit 1
}
