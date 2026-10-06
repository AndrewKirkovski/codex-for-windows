param(
    [ValidateSet('Parse', 'Metadata')]
    [string] $Mode = 'Parse',
    [Parameter(Position = 0)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'
if ($Mode -eq 'Metadata') {
    $tools = @()
    foreach ($name in @('python.exe', 'py.exe', 'rg.exe', 'powershell.exe', 'pwsh.exe')) {
        $matches = @(Get-Command -Name $name -All -ErrorAction SilentlyContinue)
        $tools += [pscustomobject]@{
            name = $name
            count = $matches.Count
            command_types = @($matches | ForEach-Object { $_.CommandType.ToString() })
        }
    }
    [pscustomobject]@{
        outcome = 'valid'
        runtime = $PSVersionTable.PSVersion.ToString()
        tools = $tools
    } | ConvertTo-Json -Depth 5 -Compress
    exit 0
}
if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    [pscustomobject]@{
        outcome = 'prerequisite_missing'
        runtime = $PSVersionTable.PSVersion.ToString()
        diagnostics = @([pscustomobject]@{ id = 'POWERSHELL-FILE-001'; line = $null; column = $null })
    } | ConvertTo-Json -Depth 5 -Compress
    exit 0
}
$tokens = $null
$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $Path,
    [ref] $tokens,
    [ref] $parseErrors
) | Out-Null
$items = @()
foreach ($parseError in $parseErrors) {
    $items += [pscustomobject]@{
        id = 'POWERSHELL-SYNTAX-001'
        line = $parseError.Extent.StartLineNumber
        column = $parseError.Extent.StartColumnNumber
    }
}
$outcome = if ($items.Count -eq 0) { 'valid' } else { 'invalid' }
[pscustomobject]@{
    outcome = $outcome
    runtime = $PSVersionTable.PSVersion.ToString()
    diagnostics = $items
} | ConvertTo-Json -Depth 5 -Compress
