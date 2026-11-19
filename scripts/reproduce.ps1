[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int[]] $Sizes,
    [switch] $BuildArtifacts,
    [string] $OutputRoot = "runs"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$sizeArgument = $Sizes -join ","
$arguments = @("scripts/reproduce.js", "--sizes", $sizeArgument, "--output-root", $OutputRoot)
if ($BuildArtifacts) {
    $arguments += "--build-artifacts"
}

Push-Location $repositoryRoot
try {
    & node @arguments
    $exitCode = $LASTEXITCODE
}
catch {
    Write-Error $_
    $exitCode = 1
}
finally {
    Pop-Location
}
exit $exitCode
