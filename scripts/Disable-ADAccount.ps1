param(
    [Parameter(Mandatory = $true)]
    [string]$AccountName
)

Import-Module ActiveDirectory

# On désactive dans l'AD local
Disable-ADAccount -Identity $AccountName
Write-Output "Compte $AccountName désactivé dans l'AD local."

# On force la synchro pour propager vers Entra tout de suite
try {
    Import-Module ADSync
    Start-ADSyncSyncCycle -PolicyType Delta
    Write-Output "Synchronisation Entra Connect déclenchée."
}
catch {
    Write-Output "Note : synchro non déclenchée automatiquement. $_"
}
