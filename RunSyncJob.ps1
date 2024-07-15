using namespace System.Collections.Generic

#runsyncjob script parameters
param(
    [Parameter(Mandatory, HelpMessage = "Select Sync profile(s) to run: <UserGroup> - <DeviceGroup> - <UserOU> - <DeviceOU>")]
    [ValidateSet('UserGroup', 'DeviceGroup', 'UserOU', 'DeviceOU')][string[]]$SyncProfile,
    [ValidateRange(1, 7)][byte]$DaysToKeepLogFiles = 7,
    [switch]$SendTo
)
$nl = [System.Environment]::NewLine
    
#different user and device sync combinations, empty out or fill up collections accordingly
    
#common parameters of SyncAD2AAD script runtimes
$CommonParams = @{
    TenantID                     = ""
    AppRegistrationID            = ""
    AppSecret                    = ""
    #CertificatePath              = ""
    AzureGroupPrefix             = "AZ-"
    RunAsJob                     = $true
    OutLog                       = $false
    CreateEmptyGroup             = $true
    EnforceGroupNamingConvention = $true
    Objects2ExcludeGroup         = "ExcludeFromAD2AADSync"
    Verbose                      = $true
}
[List[string]]$ScriptOutput = @("Mirroring of AD and Azure Groupmembership started at $(Get-Date -Format "MM-dd-yyyy_HHumm"):") #collect output
switch ($PSBoundParameters['SyncProfile']) {
    'UserGroup' {
        $UserGroups = @()
        if ($UserGroups) {
            $ScriptOutput += @("Synced User Groups:$($nl)") #collect output
            Foreach ($Group in $UserGroups) {
                $ScriptOutput += & "$PSScriptRoot\Sync-ADGroups2AAD.ps1" @CommonParams -Group2Sync $Group -Objects2Sync 'Users' -DestinationGroupType UserGroup
            }
        }
        else { $ScriptOutput += "No User groups to sync$($nl)" }
    }
    'DeviceGroup' {
        $DeviceGroups = @("XDR-PilotUsers", "Teams-TestUsers")
        if ($DeviceGroups) {
            $ScriptOutput += @("Synced Device Groups:$($nl)") #collect output
            Foreach ($Group in $DeviceGroups) {
                $ScriptOutput += & "$PSScriptRoot\Sync-ADGroups2AAD.ps1" @CommonParams -Group2Sync $Group -Objects2Sync 'All' -DestinationGroupType DeviceGroup
            }
        }
        else { $ScriptOutput += "No Device groups to sync$($nl)" }
    }
    'UserOU' {
        $UserOUs2Sync = @(
            'OU=Applications,OU=AD-Azure,OU=Groups,OU=HQ,DC=Company,DC=be',
            'OU=Sharepoint,AD-Azure,OU=Groups,OU=HQ,DC=Company,DC=be'
        )
        if ($UserOUs2Sync) {
            $ScriptOutput += @("Synced User OUs:$($nl)") #collect output
            Foreach ($Ou2Sync in $UserOUs2Sync) {
                $ScriptOutput += & "$PSScriptRoot\Sync-ADGroups2AAD.ps1" @CommonParams -OU2Sync $Ou2Sync -Objects2Sync 'Users' -DestinationGroupType UserGroup
            }
        }
        else { $ScriptOutput += "No User OUs to sync$($nl)" }
    }
    'DeviceOU' {
        $DeviceOUs2Sync = @()
        if ($DeviceOUs2Sync) {
            $ScriptOutput += @("Synced Device OUs:$($nl)") #collect output
            Foreach ($Ou2Sync in $DeviceOUs2Sync) {
                $ScriptOutput += & "$PSScriptRoot\Sync-ADGroups2AAD.ps1" @CommonParams -OU2Sync $Ou2Sync -Objects2Sync 'All' -DestinationGroupType DeviceGroup
            }
        }
        else { $ScriptOutput += "No Device OUs to sync$($nl)" }
    }
    default { Write-Warning -Message "No sync profile has been selected, exiting script..."; exit }
}
#collect all output into 1 log file and optionally send it to email recipients
$Now = Get-Date -Format "MM-dd-yyyy_HHumm"
$LogFilePath = Join-Path -Path $PSScriptRoot -ChildPath "AD2AAD_SyncReport_$($Now).log"
Out-File -FilePath $LogFilePath -InputObject $ScriptOutput -Encoding unicode -NoClobber -Force
if ($SendTo.IsPresent) {
    try {
        $Body = "Dear colleagues,$($nl)$($nl)"
        $Body += "In attachment the latest AD-Azure Sync test report"
        $Body += "$($nl)$($nl)$($nl)Kind Regards,$($nl)$($nl)$($nl)"
        $MailProps = @{
            From        = "AD2AADSyncRoutine@company.be"
            To          = @('recipient@company.be')
            Subject     = "Sync ADgroups with Azure AD"
            Body        = $Body
            Attachments = $LogFilePath
            Priority    = 'Low'
            SmtpServer  = 'smtp.company.be'
        }
        Send-MailMessage @MailProps
    }
    catch {
        Write-Error -Message "Something went wrong sending report to recipient(s): $($Recipient -join ',')!$($nl)"
    }
}
Write-Output "Last Azure Sync test output saved to $($LogFilePath)"
if ($DaysToKeepLogFiles) {
    Write-Verbose -Message "Removing logfiles older than $($DaysToKeepLogFiles) days..."
    Get-ChildItem -Path $PSScriptRoot -Filter "*.log" | Where-Object { $_.CreationTime -lt [datetime]::Today.AddDays(-$DaysToKeepLogFiles) } | Remove-Item -Confirm:$false
}