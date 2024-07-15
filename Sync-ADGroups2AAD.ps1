#Requires -Version 5.1
#Requires -PSEdition Desktop
[cmdletbinding(DefaultParameterSetName = "OUSync", SupportsShouldProcess, ConfirmImpact = 'Medium')]

<#
	.SYNOPSIS
	Sync (nested) On-prem AD groups containing users and/or devices with Azure AD groups containing users and/or primary/owned/registered devices.
	.DESCRIPTION
	Used for populating Azure AD groups with users and/or devices owned or registered by on-prem AD user object.
	Can process nested AD group membership into flat Azure AD group.
	Note: Names of both groups must be identical without the set prefix and suffix (on Azure side).
	Note: Groupnames may not contain spaces, underscores, non-ASCII characters or the used prefix (eg: AZ-) or suffixes (-U/-D) in Azure
	Uses a registered enterprise app and must have scopes as defined in local script variable <RequiredScopes>
	.EXAMPLE
	Sync-ADGroups2AAD -OU2Sync 'OU=Azure,OU=Groups,OU=Fabrikom,OU=Contoso,DC=com' -Objects2Sync 'Users' -DestinationGroupType 'UserGroup' -Outlog <-- ParameterSet = OUSync
	.EXAMPLE
	Sync-ADGroups2AAD -Group2Sync 'PWBI-Viewers' -Objects2Sync 'Users' -DestinationGroupType 'UserGroup' <-- ParameterSet = GroupSync
	.EXAMPLE
	Sync-ADGroups2AAD -Group2Sync 'INT-WindowsPilot*' -AzureGroupPrefix 'AZ-' -Objects2Sync 'Devices' -DestinationGroupType All 
		--> creates User AND Device AZ- prefixed group(s) in Azure based on ownership in Intune using wildcard groupname lookup in on-prem AD
	.INPUTS
	Either the full DN of 1 OU or 1 (wildcard) AD group display- or SAMaccountName
	.PARAMETER TenantID
	Azure Tenant ID to connect to
	.PARAMETER AppRegistrationID
	Enterprise App Registration ID to use for authentication and management scope
	.PARAMETER AppSecret
	Secret key of Enterprise App registration
	.PARAMETER CertificatePath
	Client Certificate for securing Graph connection request
	.PARAMETER OU2Sync
	The distinguished name of the OU to look for AD groups, can be piped thru DistinguishedName property
	.PARAMETER SearchScope
	Resolve AD groups inside an OU, either directly <OneLevel> (=default) or recursively <SubTree>'
	.PARAMETER Group2Sync
	The Name (as registered in AD) of a specific group or a wildcard for multiple matches, can be piped thru Name property
	.PARAMETER Objects2Sync
	What type of AD groupmember objects need to be processed? <Users> or <Devices> (AD computer object) or both <All>
	.PARAMETER Objects2ExcludeGroup
	Optional AD group holding objects (user/computer/group) to exclude from processing
	.PARAMETER DestinationGroupType
	What type of Azure group needs to be synced? <UserGroup> or <DeviceGroup> or both <All>
	A suffix -U or -D is used respectively for User- and DeviceGroup as to identify them in Azure and for successive processing
	.PARAMETER AzureGroupPrefix
	Used prefix for retrieval / filtering of script managed Azure groups, default prefix = AZ-
	.PARAMETER ConfirmGroups
	Compare groups existing on one side only and present for deletion if script runs interactively, otherwise output to log
	.PARAMETER CreateEmptyGroup
	Create (empty) Azure group even if on-prem Active Directory group has no members, otherwise skipped
	.PARAMETER RunAsjob
	Run script without interaction or prompts, mutes output to host and writes to log instead, 
	Skips destructive actions like deleting groups while comparing
	.PARAMETER OutLog
	Outputs verbose information (not only errors or warnings) to a logfile in runtime contextual Documents folder
	.OUTPUTS
	Verbose informational output only, no other objects are returned
	.ToDo
	call REST action in batches:
	https://learn.microsoft.com/en-us/graph/json-batching?WT.mc_id=EM-MVP-5002871
	.LINK
	https://learn.microsoft.com/en-us/graph/use-the-api
	.ROLE
	user / device admin
	.NOTES
	FileName: Sync-ADGroups2AAD
	Author: Christel Van der Herten
	Version history:
	v 1.1.0.0 - 15-07-2024 - generalize and overhaul of script conditional logic + output, ToDo: turn it into a genuine module :)
#>

param(
	[Parameter(Mandatory, HelpMessage = "Azure Tenant ID to connect to")]
	[ValidatePattern('(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})')]
	[string]$TenantID,

	[Parameter(Mandatory, HelpMessage = "Enterprise App Registration ID to use for authentication and management scope")]
	[ValidateNotNullOrEmpty()]
	[string]$AppRegistrationID,

	[Parameter(Mandatory, HelpMessage = "Secret key of Enterprise App registration")]
	[ValidateNotNullOrEmpty()]
	[string]$AppSecret,

	[Parameter(HelpMessage = "Path to a Client Certificate for securing the Graph connection request")]
	[string]$CertificatePath,

	[Parameter(ParameterSetName = "OUSync", Mandatory, HelpMessage = 'Must be a valid Distinguished Name')]
	[ValidatePattern("^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$")]
	[Alias("DistinguishedName", "DN")]
	[string]$OU2Sync,

	[Parameter(ParameterSetName = "OUSync", HelpMessage = 'Resolve AD groups only directly in an OU <OneLevel> (=default) or recursively <SubTree>')]
	[ValidateNotNullOrEmpty()][ValidateSet('OneLevel', 'SubTree', '1', '2')]
	[string]$SearchScope = 'OneLevel',

	[Parameter(ParameterSetName = "GroupSync", Mandatory, HelpMessage = 'Can be a full or partial (using wildcards) group displayname')]
	[SupportsWildcards()]
	[string]$Group2Sync,

	[Parameter(HelpMessage = 'Optional AD group holding objects (user/computer/group) to exclude from processing')]
	[string]$Objects2ExcludeGroup,

	[Parameter(Mandatory, HelpMessage = 'Select which type of objects in AD group(s) to process: <Users>, <Devices> or <All>')]
	[ValidateSet('Users', 'Devices', 'All')]
	[string]$Objects2Sync,

	[Parameter(Mandatory, HelpMessage = "Add user / device to their respective Azure <UserGroup> or <DeviceGroup> or both <All>")]
	[ValidateSet('UserGroup', 'DeviceGroup', 'All')]
	[string]$DestinationGroupType,

	[Parameter(HelpMessage = 'Prefix for Azure groupnames, eg: AZ- (=default)')]
	[ValidateNotNullOrEmpty()]
	[string]$AzureGroupPrefix = "AZ-",

	[Parameter(ParameterSetName = "OUSync", HelpMessage = 'Check presence of both AD and Azure groups. Cleanup is only possible thru interactive selection when not running as job!!!')]
	[switch]$ConfirmGroups,

	[Parameter(ParameterSetName = "OUSync", HelpMessage = 'Check duplicate Azure groups and remove copies, either interactively or automatically if running as job.')]
	[switch]$RemoveDuplicates,

	[Parameter(HelpMessage = 'Create new empty Azure group even if on-prem AD group has no members (yet).')]
	[switch]$CreateEmptyGroup,

	[Parameter(HelpMessage = 'Check naming conventions: (multiple) spaces, periods, underscores, hyphens, redundant pre- or suffix, ...')]
	[Alias("InspectGroupNames")]
	[switch]$EnforceGroupNamingConvention,

	[Parameter(HelpMessage = 'Run as job means no interactive prompts or output to console')]
	[switch]$RunAsjob,

	[Parameter(HelpMessage = 'Redirect script output to logfile in My Documents (= default). Eventual location is written to output stream')]
	[switch]$OutLog
)
	
process {
	[int]$i = 0
	Do {
		Write-Verbose -Message "Processing $($script:ADGroups.Count) AD groups (re)starting at index $($i)..."
		foreach ($ADgroup in $script:ADGroups[$i..($script:ADGroups.Count - 1)]) {
			$StartTime = Get-Date
			$i++ #running counter of current ADgroup array index
			# process only if current groupname is compliant (when enforced) else skip processing
			if (Assert-GroupName -GroupName $ADgroup.Name) {
				$ADMembers = @(Get-ADGroupMember -Identity $ADGroup -Recursive | Where-Object { $_.Name -notin @($Users2Exclude + $Devices2Exclude) })
				#Get Azure / Intune objects related to member(s) of AD Group
				$Users2Sync = [System.Collections.Generic.List[Object]]::New()
				$Devices2Sync = [System.Collections.Generic.List[Object]]::New()
				switch ($ApplyMembershipFrom) {
					'Users' {
						$AdUsers = @($ADMembers | Where-Object { $_.ObjectClass -eq "user" })
						Write-Verbose -Message "Processing $($AdUsers.Count) AD users..."
						Foreach ($User in $AdUsers) { 
							$UPN = (Get-ADUser $User).UserPrincipalName
							switch ($ApplyMembershipTo) {
								'UserGroup' { [void]$Users2Sync.Add(($script:AADUsers | Where-Object UserPrincipalName -eq $UPN )) } 
								'DeviceGroup' { Get-MDMDevices -UPN $UPN | ForEach-Object { [void]$Devices2Sync.Add($_) } } 
							}
						}
					}
					'Devices' {
						$AdComputers = @($ADMembers | Where-Object { $_.ObjectClass -eq "computer" })
						Write-Verbose -Message "Processing $($AdComputers.Count) AD Computers..."
						Foreach ($Device in $AdComputers) {
							$MdmDevices = @(Get-MDMDevices -DeviceName $Device.Name) #multiple return by name is possible!
							switch ($ApplyMembershipTo) {
								'UserGroup' {
									$MdmDevices | ForEach-Object {
										[void]$Users2Sync.Add(((Get-MgDeviceRegisteredUser -DeviceId $_.Id) | ForEach-Object { $script:AADUsers | Where-Object Id -eq $_.id } ))
									}
								}
								'DeviceGroup' { [void]$Devices2Sync.Add($MdmDevices) } 
							}
						}
					}
				}
				#Add retrieved Azure / Intune objects to related AzureGroup
				$AzureGroupName = "$($AzureGroupPrefix)$($ADGroup.Name.Trim())"
				switch ($ApplyMembershipTo) {
					'UserGroup' {
						$Users2Sync = $Users2Sync | Sort-Object -Property ID -Unique #filter out doubles based on ID
						Write-Verbose -Message "Found $($Users2Sync.Count) Azure User Id's"
						Sync-AzureGroupMembership -AzureGroupName "$($AzureGroupName)-U" -Users $Users2Sync
					}
					'DeviceGroup' {
						$Devices2Sync = $Devices2Sync | Sort-Object -Property ID -Unique #filter out doubles based on ID
						Write-Verbose -Message "Found $($Devices2Sync.Count) Azure Device Id's"
						Sync-AzureGroupMembership -AzureGroupName "$($AzureGroupName)-D" -Devices $Devices2Sync
					}
				}
				$PassTime = New-TimeSpan -Start $StartTime
				Write-Verbose -Message "Info: Sync of $($ADGroup.Name) took $($PassTime.Hours) hours, $($PassTime.Minutes) minutes and $($PassTime.Seconds) seconds"
				#if less than 10 minutes token lifetime left then pause loop, renew token and connect again for further processing
				if ($script:TokenExpiry -lt $((Get-Date).AddSeconds(600))) { 
					Start-Sleep -Seconds (5..15 | Get-Random) #time out between loops to prevent throttling
					break 
				}
			}
			else { continue }
		}#foreach ADgroup
		if ($script:TokenExpiry -lt $((Get-Date).AddSeconds(600))) {
			$PassTime = New-TimeSpan -Start $ScriptStartTime
			[Void]$script:Output.add("Info: Script is running for $($PassTime.Hours) hours, $($PassTime.Minutes) minutes and $($PassTime.Seconds) seconds")
			$script:GraphConnection = & "$PSScriptRoot\ConnectTo-Graph" @ConnectParams
			if ($script:GraphConnection) {
				$script:TokenExpiry = $((Get-Date).AddSeconds($script:GraphConnection.expires_in))
				[void]$Script:Output.Add("WARNING: Token has been renewed and remains valid until $($script:TokenExpiry)") 
				$script:GraphHeader = @{ 'Authorization' = $script:GraphConnection.access_token }
				if (([version]$AuthModule.Version).Major -lt 2) { $AccessToken = $script:GraphConnection.access_token }
				else { $AccessToken = ($script:GraphConnection.access_token | ConvertTo-SecureString -AsPlainText -Force) }
				Connect-MgGraph -AccessToken $AccessToken
			}
			else {
				$Message = "Failure to renew token, syncing cannot continue, halting script execution..."
				[void]$script:Output.add("Error: $($Message)")
				$ConfirmGroups.IsPresent = $false
				Write-Error -Message $Message -ErrorAction Stop
				break
			}
		}
	} Until ($i -ge $script:ADGroups.Count)
	if ($ConfirmGroups.IsPresent) {
		#https://learn.microsoft.com/en-us/graph/delta-query-overview#use-delta-query-to-track-changes-in-a-resource-collection --> get delta update or full refresh?
		$script:AADGroups = @(Get-MgGroup -All -Filter "startsWith(DisplayName, '$($AzureGroupPrefix)')" -OrderBy DisplayName -ConsistencyLevel eventual -Count AzGroupCount)
		Write-Verbose -Message "Comparing $($AzGroupCount) Azure with onprem AD groups..."
		Confirm-GroupSync -AzureGroups $script:AADGroups -ADGroups $script:ADGroups
	}
}

begin {
	#region script variables
	[version]$ScriptVersion = '1.1.0.0'
	$nl = [System.Environment]::NewLine
	#array for holding script output
	$ExecutingUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	$ScriptDescription = "Sync-ADGroups2AAD v{0} run by {1}" -f $ScriptVersion, $ExecutingUser
	$ScriptStartTime = Get-Date
	[System.Collections.Generic.List[string]]$Script:Output = @("Info: Starting $($ScriptDescription) on $($ScriptStartTime)")
	#save connection parameters in splatted hash table to renew token if necessary during script execution
	$ConnectParams = @{
		TenantID          = $TenantID
		AppRegistrationID = $AppRegistrationID
		AppSecret         = $AppSecret
	}
	if ($PSBoundParameters.ContainsKey('CertificatePath')) { $ConnectParams['CertificatePath'] = $CertificatePath }
	$script:GraphConnection = & "$PSScriptRoot\ConnectTo-Graph" @ConnectParams
	if ($script:GraphConnection) {
		#https://learn.microsoft.com/en-us/azure/active-directory-b2c/configure-tokens?pivots=b2c-user-flow --> app registration token lifetime
		$script:TokenExpiry = $((Get-Date).AddSeconds($script:GraphConnection.expires_in))
		$null = [void]$Script:Output.Add("INFO: Token is acquired and valid until $($script:TokenExpiry)")
		$script:GraphHeader = @{ 'Authorization' = $script:GraphConnection.access_token }
		#https://security.stackexchange.com/questions/108662/why-is-bearer-required-before-the-token-in-authorization-header-in-a-http-re
		#$script:GraphHeader = @{ 'Authorization' = "Bearer $script:GraphConnection.access_token" }
		#https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/2123 --> authentication token must be secure starting from version 2.0.0.0
		$AuthModule = Get-InstalledModule -Name Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
		if (([version]$AuthModule.Version).Major -lt 2) { $AccessToken = $script:GraphConnection.access_token }
		else { $AccessToken = ($script:GraphConnection.access_token | ConvertTo-SecureString -AsPlainText -Force) }
		try { Connect-MgGraph -AccessToken $AccessToken } catch { Write-Error -Message $_.Exception; exit 1 }
		#minimum required scopes for this script to function properly, more is no problem :)
		$RequiredScopes = @("Group.ReadWrite.All", "GroupMember.ReadWrite.All", "Device.Read.All", "DeviceManagementManagedDevices.Read.All")
		$MgContext = Get-MgContext
		#[Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthContext.Scopes
		$MissingScopes = Compare-Object -ReferenceObject $RequiredScopes -DifferenceObject $MgContext.Scopes -PassThru | Where-Object { $_.SideIndicator -eq '<=' }
		if ($MissingScopes) {
			[void]$Script:Output.Add("ERROR: Exiting script due to missing required scopes on App Registration <$($MgContext.AppName)>:$($nl)$($MissingScopes)")
			Write-Error -Message $Script:Output[-1] -ErrorAction Stop
		}
	}
	else {	Write-Error -Message "Failed to create a Microsoft Graph connection, exiting script..." -ErrorAction Stop }
	#do not prompt for input if script is run as scheduled task
	if ($RunAsjob.IsPresent) { $ConfirmPreference = 'none'; $WhatIfPreference = $false; }
	#interpret incoming parameters and set script local variables
	$Groups2Exclude = $Users2Exclude = $Devices2Exclude = @()
	#Retrieve AD objects to exclude from syncing
	if ($PSBoundParameters.ContainsKey('Objects2ExcludeGroup')) {
		if (Get-ADGroup $Objects2ExcludeGroup) {
			$Members2Exclude = Get-ADGroupMember -Identity $Objects2ExcludeGroup
			$Groups2Exclude = @($Members2Exclude | Where-Object { $_.ObjectClass -eq 'group' } | Select-Object Name )
			$Groups2Exclude += $Objects2ExcludeGroup
			$Users2Exclude = @($Members2Exclude | Where-Object { $_.ObjectClass -eq 'user' } | Select-Object Name )
			$Devices2Exclude = @($Members2Exclude | Where-Object { $_.ObjectClass -eq 'computer' } | Select-Object Name )
		}
		else {
			[void]$Script:Output.Add("ERROR: Exclusion Group $($Objects2ExcludeGroup) not found! Exiting script to prevent sync of to be excluded objects...")
			Write-Error -Message $Script:Output[-1] -ErrorAction Stop
		}
	}
	switch ($PSCmdlet.ParameterSetName) {
		'OUSync' {
			if (-not(Get-ADOrganizationalUnit -Identity $OU2Sync)) { [void]$Script:Output.Add( "WARNING: OU lookup failed, skipping <$($OU2Sync)>"); break }
			$script:ADGroups = @(Get-ADGroup -Filter * -SearchBase $OU2Sync -SearchScope $SearchScope | Where-Object { $_.Name -notin $Groups2Exclude })
			[void]$Script:Output.Add("Processing $($script:ADGroups.Count) AD group(s) retrieved from OU: $($OU2Sync)")																																																			
		}
		'GroupSync' {
			$script:ADGroups = @(Get-ADgroup -Filter "Name -like '$Group2Sync'" | Where-Object { $_.Name -notin $Groups2Exclude }) 
			[void]$Script:Output.Add("Processing $($script:ADGroups.Count) AD group(s) matching groupname filter: $($Group2Sync)")
		}																																														
	}
	if (-not ($script:ADGroups.Count)) { throw "No AD groups retrieved, nothing to sync, exiting script..."; Exit 1 }
	#replace <All> with array of all objects to sync from and to
	switch ($Objects2Sync) {
		'All' { $ApplyMembershipFrom = @('Users', 'Devices') }
		Default { $ApplyMembershipFrom = @($Objects2Sync) }
	}
	switch ($DestinationGroupType) {
		'All' { $ApplyMembershipTo = @('UserGroup', 'DeviceGroup') }
		Default { $ApplyMembershipTo = @($DestinationGroupType) }
	}
	$script:CompanyUPNs = @((Get-ADForest).UPNSuffixes) #get used UserPrincipalName(s) present in onprem AD
	[System.IO.DirectoryInfo]$script:LogsDirectory = [System.Environment]::GetFolderPath('mydocuments') #set default logfile save location
	[regex]$script:AzureAdditions = "(?i)(?'Prefix'^($($AzureGroupPrefix)))(?'Name'.*)(?'Suffix'(-[U|D])$)" #use for validation of Azure GroupName(s)
	[int]$script:MaxGroupNameLength = 64 - $AzureGroupPrefix.Length - 2 #max length of Azure GroupName minus Azure prefix parameter and suffix -U or -D 
	[void]$Script:Output.Add( "INFO: GroupMember object types to sync from: AD $($ApplyMembershipFrom -join ' and ') to: Azure $($ApplyMembershipTo -join ' and ')" )
	# store AAD objects for lookups = performance boost
	# https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
	# https://learn.microsoft.com/en-us/graph/aad-advanced-queries?													
	$script:AADUsers = @(Get-MGuser -All -Filter "OnPremisesSyncEnabled eq true and UserType eq 'Member'" -ConsistencyLevel eventual -CountVariable UserCount)
	$script:AADGroups = @(Get-MgGroup -All -Filter "startsWith(DisplayName, '$($AzureGroupPrefix)')" -OrderBy DisplayName -ConsistencyLevel eventual -Count groupCount)
	#$script:AADDevices = @(Get-IntuneManagedDevice -filter "operatingSystem eq 'Windows' and deviceOwnership eq 'Company'" | Get-MSGraphAllPages)
	# $DeviceParams = @{
	# 	Filter = "operatingSystem eq 'Windows' and deviceOwnership eq 'Company'"
	# }
	#$script:AADDevices = Get-MgDeviceManagementManagedDevice @DeviceParams
	#endregion script variables
	#region #functions
	Function Expand-RESTObject {
		param([Parameter(Mandatory, ValueFromPipeline, HelpMessage = 'Must contain AdditionalProperties')]$InputObject)
		try { 
			$InputObject.AdditionalProperties.GetEnumerator() | ForEach-Object { Add-Member -InputObject $InputObject -MemberType NoteProperty -Name $_.Key -Value $_.value -Force } 
			#$InputObject.AdditionalProperties.Clear()
		}
		catch { Write-Warning -Message 'No Additional Properties found in InputObject! Returning as is...' }
		return $InputObject
	}

	Function Get-MDMDevices {
		[OutputType([Microsoft.Graph.PowerShell.Models.MicrosoftGraphDirectoryObject])]
		[CmdletBinding(DefaultParameterSetName = 'User')]
		param(
			[Parameter(Mandatory, ParameterSetName = 'User')]$UPN,
			[Parameter(Mandatory, ParameterSetName = 'Device')]$DeviceName,
			[Parameter(HelpMessage = "Get (optional) Registree(s) and/or Owner(s) info")]
			[switch]$UserInfo
		)
		#https://techcommunity.microsoft.com/t5/intune-customer-success/understanding-the-intune-device-object-and-user-principal-name/ba-p/3657593
		Write-Verbose -Message "Getting MDM device(s) for $($PSCmdlet.ParameterSetName): $($UPN)$($DeviceName)"
		switch ($PSCmdlet.ParameterSetName) {
			'User' {
				$UserID = ($script:AADUsers | Where-Object UserPrincipalName -eq $UPN).Id
				if ($UserID) { $Devices = @(Get-MgUserRegisteredDevice -UserId $UserID -All ) }
			}
			'Device' { $Devices = @(Get-MgDevice -Filter "displayname eq '$DeviceName'" -All ) }
		}
		if ($Devices) {
			$Devices = ($Devices | ForEach-Object { Expand-RESTObject -InputObject $_ })
			$Devices = ($Devices | Where-Object { $_.operatingSystem -eq 'Windows' -and $_.deviceOwnership -eq 'Company' })
			if ($UserInfo.IsPresent) {
				foreach ($Device in ($Devices | Where-Object { $null -ne $_ })) {
					$DevUri = "https://graph.microsoft.com/v1.0/devices/$($Device.Id)"
					$Owner = (Invoke-RestMethod -Uri "$($DevUri)/registeredOwners" -Method Get -Headers $script:GraphHeader).Value
					$Device | Add-Member -MemberType NoteProperty 'Owner' -Value $Owner
					[void]$Script:Output.Add("Owner for $($Device.displayName): $($Owner.UserPrincipalName)")
					$Registree = (Invoke-RestMethod -Uri "$($DevUri)/registeredUsers" -Method Get -Headers $script:GraphHeader).Value
					[void]$Script:Output.Add("Registree(s) for $($Device.displayName): $($Registree.UserPrincipalName -join ',')")
					$Device | Add-Member -MemberType NoteProperty 'Registree' -Value $Registree
				}#foreach
			}
		}
		switch ($Devices.Count) {
			0 { $Message = "WARNING: no Intune device object found for {0}{1}." -f $UPN, $DeviceName }
			1 { $Message = "INFO: Found single Intune device object {2} with ID {3} for {0}{1}." -f $UPN, $DeviceName, $Devices.displayName, $Devices.Id }
			{ $_ -ge 2 } { $Message = "WARNING: multiple Intune device objects found for {0}{1}: {2}." -f $UPN, $DeviceName, $($Devices.displayname -join ',') }
		}
		Write-Verbose -Message $Message
		[void]$Script:Output.Add($Message)
		return $Devices
	}

	Function Assert-GroupName {
		[OutputType([Bool])]
		param(
			[string]$GroupName
		)
		#https://learn.microsoft.com/en-us/office/troubleshoot/office-suite-issues/username-contains-special-character
		#https://climbtheladder.com/10-azure-ad-group-naming-best-practices/
		$Warnings = @()
		switch ($GroupName) {
			{ $GroupName -cmatch '\P{IsBasicLatin}' } { $Warnings += "non-ASCII characters" }
			{ $GroupName -match ('\s|_') } { $Warnings += "spaces or underscores" }
			{ $GroupName -match ('[\.-]{2,}') } { $Warnings += "consecutive hyphens (-) or perionds (.)" }
			{ $GroupName -match "^($($AzureGroupPrefix))" } { $Warnings += "redundant $($AzureGroupPrefix) prefix" }
			{ $GroupName -match '(-[U|D])$' } { $Warnings += "redundant -U/-D suffix" }
			{ $GroupName.Length -ge $script:MaxGroupNameLength } { $Warnings += "generated Azure GroupName length greater than 64 characters" }
			default { $Asserted = $true }
		}
		if ($Warnings.Count) { 
			[string]$Message = "naming violations in AD group name <{0}>:{2}{1}" -f $GroupName, $($Warnings -join $nl), $nl
			if ($EnforceGroupNamingConvention) {
				$Asserted = $false
				$Message = "ERROR: Skipping groupsync due to " + $Message
				Write-Error -Message $Message
			}
			else {
				$Asserted = $true
				$Message = "WARNING: Found " + $Message 
				Write-Warning -Message $Message
			}
			[void]$Script:Output.add($Message)
		}
		return $Asserted
	}

	Function Sync-AzureGroupMembership {
		[OutputType([System.Void])]
		[CmdletBinding(DefaultParameterSetName = 'User', SupportsShouldProcess, ConfirmImpact = 'Medium')]
		param(
			$AzureGroupName,
			[Parameter(ParameterSetName = 'User')]$Users,
			[Parameter(ParameterSetName = 'Device')]$Devices
		)
		if ($PSCmdlet.ShouldProcess("Sync membership of $($PSCmdlet.ParameterSetName)s to $($AzureGroupName)", $AzureGroupName, 'Sync GroupMembership')) {
			#$GroupUri = "https://graph.microsoft.com/v1.0/groups/?`$filter=displayName eq $($AzureGroupName)"
			#$AzureADGroup = (Invoke-RestMethod -Method Get -Uri $GroupUri -Headers $script:GraphHeader).Value
			$AzureADGroup = Get-MgGroup -Filter "DisplayName eq '$AzureGroupName'"
			if (-not ($AzureADGroup)) {
				if ($Users -or $Devices -or $CreateEmptyGroup.IsPresent) {
					try { 
						$body = [ordered]@{
							"description"     = $ScriptDescription
							"displayName"     = $AzureGroupName
							"groupTypes"      = @()
							#"isAssignableToRole" = $true
							"mailEnabled"     = $false
							"mailNickname"    = $AzureGroupName
							"securityEnabled" = $true
						} | ConvertTo-Json
						$NewGroupUri = "https://graph.microsoft.com/v1.0/groups"
						Invoke-RestMethod -Method Post -Uri $NewGroupUri -Headers $script:GraphHeader -Body $body -ContentType application/json
						$AzureADGroup = Get-MgGroup -Filter "DisplayName eq '$AzureGroupName'"
						if ($AzureADGroup) { [void]$script:Output.Add( "GroupMembership: Created new \ empty Azure group: $($AzureADGroup.displayName)") }
						else { throw "Azure group <$($AzureGroupName)> creation failed..." }
					}
					catch { [void]$Script:Output.Add( "ERROR: $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $NewGroupUri)") }
				}
			}
			if ($AzureADGroup) {
				Write-Verbose -Message ("Getting members for Azure group: {0}({1})" -f $AzureGroupName, $AzureADGroup.Description)
				$ExistingMembers = @(Get-MgGroupMember -GroupId $AzureADGroup.Id -All | ForEach-Object { Expand-RESTObject -InputObject $_ })
				switch ($PSCmdlet.ParameterSetName) {
					'User' {
						#use lookup as filter so non-AD users will NOT be processed!
						$ManagedMembers = @($ExistingMembers | Where-Object { ($_.UserPrincipalName -in $script:AADUsers.UserPrincipalName) })
						#unmanaged and/or stale accounts for future reporting?
						#$OtherMembers = @($ExistingMembers -notin $ManagedMembers) 
						$Members2Compare = $Users
					}
					'Device' { 
						#only corporate devices expected so no filter (yet)
						$ManagedMembers = $ExistingMembers #| Where-Object { ($_.Name -in $script:AADDevices.displayName) })
						$Members2Compare = $Devices 
					}
				}
				if ($Members2Compare) {
					#compare AD <-> Azure group membership
					if ($ManagedMembers) { $Members2Sync = Compare-Object -ReferenceObject $ManagedMembers -DifferenceObject $Members2Compare -Property Id -PassThru }
					else { 
						Write-Verbose -Message "Syncing ALL AD onprem users/devices to (new) Azure group..." #add SideIndicator explicitly for sync routine
						$Members2Sync = $Members2Compare 
						$Members2Sync | Add-Member -MemberType NoteProperty -Name 'SideIndicator' -Value "=>" -ErrorAction SilentlyContinue
					}
				}
				else {
					Write-Verbose -Message "Empty AD group found, removing all (AD managed) members from Azure group..."
					$Members2Sync = $ManagedMembers
					$Members2Sync | Add-Member -MemberType NoteProperty -Name 'SideIndicator' -Value "<=" -ErrorAction SilentlyContinue
				}
				if ($Members2Sync) {
					[void]$Script:Output.Add( "GroupMembership: Found $($Members2Sync.Count) $($PSCmdlet.ParameterSetName) objects to sync to $($AzureGroupName). Processing..." )
					$Members2Add = @($Members2Sync | Where-Object { $_.SideIndicator -eq '=>' })
					$Members2Remove = @($Members2Sync | Where-Object { $_.SideIndicator -eq '<=' })
					if ($Members2Add) {
						if ($Members2Add.Count -gt 1){
							#batch adding members see: https://learn.microsoft.com/en-us/graph/api/group-post-members?view=graph-rest-1.0&tabs=http#request-1
							$GraphBatchSize = 20 #current max batch size in Graph SDK
							for ($i = 0; $i -lt $Members2Add.count; $i += $GraphBatchSize) {
								$UpperBound = $i + $GraphBatchSize - 1 #subtract 1 = offset between count and index
								$MembersBatch = @($Members2Add[$i..$UpperBound]) #array upperbound retrieval is handled gracefully in POSH
								Write-Verbose -Message "Processing $($MembersBatch.Count) Members2Sync starting from index $($i) to $($UpperBound)"
								$MembersDataBind = @()
								foreach ($Member2Add in $MembersBatch) { $MembersDataBind += "https://graph.microsoft.com/v1.0/directoryObjects/$($Member2Add.Id)" }
								$body = @{"members@odata.bind" = $MembersDataBind } | ConvertTo-Json
								$GroupUri = "https://graph.microsoft.com/v1.0/groups/$($AzureADGroup.Id)"
								try {
									Invoke-RestMethod -Method Patch -Uri $GroupUri -Headers $script:GraphHeader -Body $body -ContentType application/json
									$Action = "added to"
									#Update-MgGroup -GroupId $groupId -BodyParameter $body
								}
								catch { 
									[void]$Script:Output.Add( "ERROR: $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $GroupUri )")
									$Action = 'FAILED adding to'
								}
								$Message = "GroupMembership: {0} {1} {2}" -f $($MembersBatch.displayname -join ','), $Action, $AzureADGroup.displayName
								[void]$Script:Output.Add( $Message )
								Write-Verbose -Message $Message
							}
						}
						else {
							foreach ($Member2Add in $Members2Add) {
								#add onprem user/device to Azure group
								$GroupUri = "https://graph.microsoft.com/v1.0/groups/$($AzureADGroup.Id)/members/`$ref"
								$body = [ordered]@{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($Member2Add.Id)" } | ConvertTo-Json
								try {
									#New-MgGroupMemberByRef -GroupId $AzureADGroup.Id -BodyParameter $body
									Invoke-RestMethod -Method Post -Uri $GroupUri -Headers $script:GraphHeader -Body $body -ContentType application/json
									$Action = 'added to'
								}
								catch { 
									[void]$Script:Output.Add( "ERROR: $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $GroupUri )")
									$Action = 'FAILED adding to'
								}
								$Message = "GroupMembership: {0} {1} {2}" -f $Member2Add.displayName, $Action, $AzureADGroup.displayName
								[void]$Script:Output.Add( $Message )
								Write-Verbose -Message $Message
							}
						}
					}
					if ($Members2Remove) {
						#no batch processing possible (yet) for removing members
						foreach ($Member2Remove in $Members2Remove) {
							#remove user/device from Azure group
							#see https://docs.microsoft.com/en-us/graph/api/group-delete-members?view=graph-rest-1.0&tabs=http
							$GroupUri = "https://graph.microsoft.com/v1.0/groups/$($AzureADGroup.Id)/members/$($Member2Remove.Id)/`$ref"
							try {
								#Remove-MgGroupMemberByRef -GroupId $AzureADGroup.Id -DirectoryObjectId $Member2Remove.Id
								Invoke-RestMethod -Method Delete -Uri $GroupUri -Headers $script:GraphHeader
								$Action = 'removed from'
							}
							catch { 
								[void]$Script:Output.Add("ERROR: $(Resolve-GraphRequestError -Response $_.Exception.Response -GraphUri $GroupUri)")
								$Action = 'FAILED removing from'
							}
							$Message = "GroupMembership: {0} {1} {2}" -f $Member2Remove.displayName, $Action, $AzureADGroup.displayName
							[void]$Script:Output.Add( $Message )
							Write-Verbose -Message $Message
						}
					}
				}
				else { [void]$script:Output.Add( "GroupMembership: No difference between AD and Azure members found, nothing to sync... ") }
			}
		}
		else { Write-Warning -Message "Syncing membership of $($PSCmdlet.ParameterSetName)s to $($AzureGroupName) has been skipped due to ConfirmImpact set to: $($ConfirmPreference)" }
	}
	Function Confirm-GroupSync {
		[OutputType([System.Void])]
		param(
			$AzureGroups,
			$ADGroups
		)
		$DuplicateAadGroups = @($AzureGroups | Group-Object -Property DisplayName | Where-Object Count -gt 1)
		if ($DuplicateAadGroups) {
			$SelectProps = @('Displayname', 'Id', 'MemberCount', 'CreatedDateTime')
			foreach ($Group in $DuplicateAadGroups) {
				[void]$script:Output.add("Warning: Found duplicates for $($Group.DisplayName)")
				foreach ($DuplicateAadGroup in $Group.Group) {
					Get-MgGroupMember -GroupId $DuplicateAadGroup.Id -CountVariable MemberCount -ConsistencyLevel eventual
					Write-Host "Found $($MemberCount) members in: $($DuplicateAadGroup.DisplayName) ($($DuplicateAadGroup.Id))"
					Add-Member -InputObject $DuplicateAadGroup -MemberType NoteProperty -Name "MemberCount" -Value $MemberCount
				}
				if ($RemoveDuplicates) {
					$Groups2Remove = $Group.Group | Sort-Object MemberCount, CreatedDateTime -Descending | Select-Object -Last ($Group.Group.Count - 1) -Property $SelectProps
					if (-not $RunAsjob) { $Groups2Remove | Select-Object -Property $SelectProps | Out-GridView -Title 'Select duplicate group(s) to remove' -PassThru | ForEach-Object { Remove-MgGroup -GroupId $_.Id -Confirm } }
					else { $Groups2Remove | ForEach-Object { Remove-MgGroup -GroupId $_.Id -Confirm:$false } }
				}
			}
		}
		Write-Verbose -Message "INFO: Checking $($AzureGroups.Count) Azure groups for existence in on-prem AD"
		ForEach ($AzureGroup in $AzureGroups) {
			$NameParts = $script:AzureAdditions.Match($AzureGroup.displayName).Groups
			try {
				if ($BaseName = $NameParts['Name'].Value) {
					switch ($NameParts['Suffix'].Value) {
						'-U' { $GroupType = 'UserGroup' }
						'-D' { $GroupType = 'DeviceGroup' }
						default { [void]$Script:Output.add("WARNING: Suffix mismatch in Azure GroupName: $($AzureGroup.displayName)") }
					}
					if (-not ($ADGroups | Where-Object { $_.Name -eq $BaseName })) {
						Write-Verbose -Message "Trying to find matching AD group outside of current processing scope"
						try { Get-ADGroup -Identity $BaseName }
						catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
							$Message = "$($GroupType) <$($AzureGroup.displayName)> only exists in Azure!"
							#remove Azure only group(s) but only if selected by human interaction!
							if (-not $RunAsjob.IsPresent) {
								Write-Warning -Message $Message
								try { Remove-MgGroup -ObjectId $AzureGroup.Id -Confirm }
								catch { Write-Error -Message $_.Exception }
							}
							else { [void]$Script:Output.add("WARNING: $($Message)") }
						}
						catch { Write-Error -Message $_.Exception }
					}
				}
				else { [void]$Script:Output.add("WARNING: Naming Convention mismatch in Azure GroupName: $($AzureGroup.displayName)") }
			}
			catch { [void]$Script:Output.add("ERROR: $($_.Exception)") }
		}#foreach AzureGroup
	}

	Function Resolve-GraphRequestError {
		param(
			$Response,
			$GraphUri
		)
		$HelpUri = "https://docs.microsoft.com/en-us/graph/errors"
		Write-Warning -Message "HTTP Status Code $($Response.StatusCode.value__) encountered, see $($HelpUri). "
		$reader = New-Object System.IO.StreamReader($Response.GetResponseStream())
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$output = $reader.ReadToEnd()
		<# switch ($Response.StatusCode){
			404 {"Not Found"}
			408 {"Request Timeout"}
			429 {"Too Many Requests, throttling..."}
			500 {"Internal Server Error"}
			503 {"Service Unavailable"}
			504 {"Gateway Timeout"}
			default {"Unknown error"}
		}   #> 
		Write-Verbose -Message "Graph request <$($GraphUri)> failed with HTTP Status $($Response.StatusCode) $($Response.StatusDescription)"
		return $output
	}
	Function Write-Log {
		$PassTime = New-TimeSpan -Start $ScriptStartTime
		[void]$script:Output.add("Info: Script total runtime is $($PassTime.Hours) hours, $($PassTime.Minutes) minutes and $($PassTime.Seconds) seconds")
		if ($OutLog.IsPresent) {
			$Now = Get-Date -Format "MM-dd-yyyy_HHumm-ss"
			switch ($PSCmdlet.ParameterSetName) {
				'OUSync' { $LogFileName = "AD2AAD-OU_SyncReport_$($Now).log" }
				'GroupSync' { $LogFileName = "AD2AAD-Group_SyncReport_$($Now).log" }
				default { $LogFileName = "AD2AAD_SyncReport_$($Now).log" }
			}
			$LogFilePath = Join-Path -Path $script:LogsDirectory -ChildPath $LogFileName
			try { [io.file]::OpenWrite($LogFilePath).close() }
			#assuming!!! user temp folder is always writable within runtime context
			catch { $LogFilePath = Join-Path -Path $env:TEMP -ChildPath $LogFileName } 
			$Script:Output | Out-File -FilePath $LogFilePath -Force
			Write-Output "Saved AD2AAD $($PSCmdlet.ParameterSetName) on $(Get-Date) to file: $($LogFilePath)"
		}
		else { $Script:Output }
	}
	#endregion #functions
	#https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_trap?view=powershell-5.1
	trap { Write-Log } 
}

end {
	Write-Log
}
