<#	
===========================================================================
	Created by:   	barkz@purestorage.com
	Organization: 	Pure Storage, Inc.
	Filename:     	PureStorageOpenConnectMicrosoftAzure.psm1
	Copyright:		(c) 2016 Pure Storage, Inc.
	Github:			https://github.com/purestorage-microsoftazure
	-------------------------------------------------------------------------
	Module Name: PureStorageOpenConnectMicrosoftAzure
	Development Tool: https://github.com/adamdriscoll/poshtools
	Installer Tool: http://wixtoolset.org/
#>
<#
	Disclaimer
	The sample script and documentation are provided AS IS and are not supported by 
	the author or the author?s employer, unless otherwise agreed in writing. You bear 
	all risk relating to the use or performance of the sample script and documentation. 
	The author and the author?s employer disclaim all express or implied warranties 
	(including, without limitation, any warranties of merchantability, title, infringement 
	or fitness for a particular purpose). In no event shall the author, the author?s employer 
	or anyone else involved in the creation, production, or delivery of the scripts be liable 
	for any damages whatsoever arising out of the use or performance of the sample script and 
	documentation (including, without limitation, damages for loss of business profits, 
	business interruption, loss of business information, or other pecuniary loss), even if 
	such person has been advised of the possibility of such damages.
#>

#region Helper-Functions
if (-not (Get-Module -Name 'Azure')) {
	try {
		#Import-Module 'C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Azure.psd1'
	} catch {
		Write-Error "Please install the Microsoft Azure PowerShell Module."
	}
}

if (-not (Get-Module -Name 'ExpressRoute')) {
	try {
		#Import-Module 'C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\ExpressRoute\ExpressRoute.psd1'
	} catch {
		Write-Error "Please install the Microsoft Azure PowerShell Module."
	}
}

if (-not (Get-Module -Name 'PureStoragePowerShellSDK')) {
	try {
		Import-Module 'PureStoragePowerShellSDK'
	} catch {
		Write-Error "Please install the Pure Storage PowerShell SDK."
	}
}

if (-not (Get-Module -Name 'PureStoragePowerShellToolkit')) {
	try {
	Import-Module 'PureStoragePowerShellToolkit'
		} catch {
		Write-Error "Please install the Pure Storage PowerShell Toolkit."
	}
}

#endregion

#region New-PsOpenConnectConfiguration
#
# DEMO SCRIPT
#
function New-OpenConnectConfiguration() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile="C:\MyAzure\MicrosoftAzureCustomConfiguration.xml"
)
    if(-not $response) { 
	    $response = Add-AzureAccount
    }
    
    $xml=$null
	[xml]$xml = Get-Content $ConfigurationFile #C:\MyAzure\MicrosoftAzureCustomConfiguration.xml 
	
    $AzureCircuitName = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.CircuitName
	[int]$Bandwidth = [convert]::ToInt32($xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.Bandwidth, 10)
	$Location = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.Location
	$ServiceProviderName = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.ProviderName
	$BillingType = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BillingType
	$Sku = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.Sku
	$ASN = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.ASN
	$private_Subnet_Primary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Private.Primary
	$private_Subnet_Secondary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Private.Secondary
	$VLANPrivate = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Private.VLAN
	$public_Subnet_Primary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Public.Primary
	$public_Subnet_Secondary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Public.Secondary
	$VLANPublic = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Public.VLAN

    #DEMO--New-AzureDedicatedCircuit -CircuitName $AzureCircuitName -Bandwidth $Bandwidth -BillingType $BillingType -Location $Location -ServiceProviderName $ServiceProviderName -Sku $Sku
	$ServiceKey = (Get-AzureDedicatedCircuit).ServiceKey 

	#DEMO--New-AzureBGPPeering -ServiceKey $ServiceKey -PrimaryPeerSubnet $private_Subnet_Primary -SecondaryPeerSubnet $private_Subnet_Secondary -PeerAsn $ASN -AccessType Private -VlanId $VLANPrivate
	#DEMO--New-AzureBGPPeering -ServiceKey $ServiceKey -PrimaryPeerSubnet $public_Subnet_Primary -SecondaryPeerSubnet $public_Subnet_Secondary -PeerAsn $ASN -AccessType Public -VlanId $VLANPublic 
    
    Write-Host "Microsoft Azure Dedicated Circuit Status for"$response.Id -ForegroundColor Yellow -NoNewline
	Get-AzureDedicatedCircuit -ServiceKey $ServiceKey
}
#endregion

#region Update-PsOpenConnectConfiguration
function Update-OpenConnectConfiguration() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile
)
	$response = Add-AzureAccount

	[xml]$xml = Get-Content $ConfigurationFile
	$ASN = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.ASN
	$private_Subnet_Primary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Private.Primary
	$private_Subnet_Secondary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Private.Secondary
	$VLANPrivate = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Private.VLAN
	$public_Subnet_Primary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Public.Primary
	$public_Subnet_Secondary = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Public.Secondary
	$VLANPublic = $xml.OpenConnectMicrosoftAzure.ExpressRouteConfiguration.BorderGatewayProtocolPeering.Public.VLAN

	Set-AzureBGPPeering -ServiceKey $ServiceKey -PrimaryPeerSubnet $private_Subnet_Primary -SecondaryPeerSubnet $private_Subnet_Secondary -PeerAsn $ASN -VlanId $VLANPrivate –AccessType Private
		
	Set-AzureBGPPeering -ServiceKey $ServiceKey -PrimaryPeerSubnet $public_Subnet_Primary -SecondaryPeerSubnet $public_Subnet_Secondary -PeerAsn $ASN -VlanId $VLANPublic –AccessType Public
	Remove-AzureBGPPeering -ServiceKey $ServiceKey -AccessType Public -Force
}
#endregion

#region Remove-PsOpenConnectConfiguration
function Remove-OpenConnectConfiguration() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile
)
	$response = Add-AzureAccount
	Remove-AzureBGPPeering -ServiceKey $ServiceKey -AccessType Private -Force
	Remove-AzureBGPPeering -ServiceKey $ServiceKey -AccessType Public -Force
}
#endregion

#region New-PsOpenConnectExpressRoute
#
# DEMO SCRIPT
#
function New-OpenConnectExpressRoute() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile="C:\MyAzure\MicrosoftAzureCustomConfiguration.xml"
	)

    $xml=$null
    [xml]$xml = Get-Content $ConfigurationFile
	
    #DEMO--Set-AzureVNetConfig -ConfigurationPath $VNetConfigXML
	#REPORT--Get-AzureVNetConfig | Format-List
	#ADD_CMDLET--Remove-AzureVNetConfig

	$VNetName = $xml.OpenConnectMicrosoftAzure.AzureConfiguration.VirtualNetworkName
	#DEMO--New-AzureVNetGateway -VNetName $VNetName -GatewayType 'DynamicRouting'

	$LocalNetworkSiteName = $xml.OpenConnectMicrosoftAzure.AzureConfiguration.LocalNetworkSiteName
	#REPORT--Get-AzureVNetGateway -VNetName $VNetName

	#DEMO--Set-AzureVNetGateway -VNetName $VNetName -LocalNetworkSiteName $LocalNetworkSiteName -Connect #-Debug
	#DEMO--Set-AzureVNetGateway -VNetName $VNetName -LocalNetworkSiteName $LocalNetworkSiteName -Disconnect

    $ServiceKey = (Get-AzureDedicatedCircuit).ServiceKey 
<#
    [xml]$xml = Get-Content $VNetConfigXML
	$VPNGatewayAddressNode = $xml.NetworkConfiguration.VirtualNetworkConfiguration.LocalNetworkSites.LocalNetworkSite
	$VPNGatewayAddressNode.VPNGatewayAddress = (Get-AzureVNetGateway -VNetName $VNetName).VIPAddress
	$xml.Save($VNetConfigXML)
#>
    Write-Host "Microsoft Azure Dedicated Circuit Link Status for"$response.Id -ForegroundColor Yellow -NoNewline
	Get-AzureVNetConnection -VNetName $VNetName 
	Get-AzureDedicatedCircuitLink -ServiceKey $ServiceKey
	#DEMO--New-AzureDedicatedCircuitLink -ServiceKey $ServiceKey -VNetName $VNetName
	#DEMO--Remove-AzureDedicatedCircuitLink -ServiceKey $ServiceKey -VNetName $VNetName
}
#endregion

#region Update-PsOpenConnectExpressRoute
function Update-OpenConnectExpressRoute() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile
	)
}
#endregion

#region Remove-PsOpenConnectExpressRoute
function Remove-OpenConnectExpressRoute() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile
	)
}
#endregion

#region New-OpenConnectTestVM
#
# DEMO SCRIPT
#
function New-OpenConnectTestVM() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile="C:\MyAzure\MicrosoftAzureCustomConfiguration.xml",
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $RDPPath="C:\MyAzure\"
    )

    $xml=$null
	[xml]$xml = Get-Content $ConfigurationFile 

    $VMInstanceName = $xml.OpenConnectMicrosoftAzure.AzureVirtualMachineConfiguration.VmInstanceName
	$ServiceName =  $xml.OpenConnectMicrosoftAzure.AzureVirtualMachineConfiguration.ServiceName
	$VMTemplate = $xml.OpenConnectMicrosoftAzure.AzureVirtualMachineConfiguration.VMTemplate
	#$Admin = $xml.OpenConnectMicrosoftAzure.AzureVirtualMachineConfiguration.Admin	
    #$AdminPassword = (ConvertTo-SecureString -String ($xml.OpenConnectMicrosoftAzure.AzureVirtualMachineConfiguration.AdminPassword) -AsPlainText -Force)
	$VNetName =  $xml.OpenConnectMicrosoftAzure.AzureConfiguration.VirtualNetworkName
	$InstanceSize =  $xml.OpenConnectMicrosoftAzure.AzureVirtualMachineConfiguration.InstanceSize
    $AzureSubnet = $xml.OpenConnectMicrosoftAzure.AzureVirtualMachineConfiguration.AzureSubnet	

	$Template = @( Get-AzureVMImage | where-object { $_.Label -like $VMTemplate }).ImageName
	$Image = Get-AzureVMImage -ImageName $Template
    $ServiceKey = (Get-AzureDedicatedCircuit).ServiceKey 

    #
    # DEMO SCRIPT
    #   StorageAccount[2]
    #   GeoPrimaryLocation[2]
    #
	Set-AzureSubscription -SubscriptionName ((Get-AzureSubscription | Where-Object { $_.IsDefault }).SubscriptionName).ToString() -CurrentStorageAccountName ((Get-AzureStorageAccount).StorageAccountName[2]).ToString()
	
    if( -not(Get-AzureService -ServiceName $ServiceName)) {
        New-AzureService -ServiceName $ServiceName -Location ((Get-AzureStorageAccount).GeoPrimaryLocation[2]).ToString()
    }
    $Creds = Get-Credential -Message "Enter the Username and Password to be used with $VMInstanceName"
    New-AzureVMConfig -Name $VMInstanceName -InstanceSize $InstanceSize -ImageName $Image.ImageName | `
        #Add-AzureProvisioningConfig -Windows -AdminUsername $Admin -Password $AdminPassword | `
        Add-AzureProvisioningConfig -Windows -AdminUsername $Creds.UserName -Password $Creds.Password | `
        Set-AzureSubnet -SubnetNames $AzureSubnet | `
        New-AzureVM -ServiceName $ServiceName -VNetName $VNetName -Location ((Get-AzureStorageAccount).GeoPrimaryLocation[2]).ToString() 
	

    #ADD_CMDLET--Add-AzureNetworkInterfaceConfig -VM $VM -Name 'ISCSI-1' -SubnetName 'AzureVMs' -StaticVNetIPAddress '10.2.0.8'
	#ADD_CMDLET--Add-AzureNetworkInterfaceConfig -VM $VM -Name 'ISCSI-2' -SubnetName 'AzureVMs' -StaticVNetIPAddress '10.2.0.9'
    #
    # DEMO SCRIPT
    #   ServiceName < 15 characters
    #	
	#$VM | New-AzureVM -ServiceName $ServiceName -VNetName $VNetName -Location ((Get-AzureStorageAccount).GeoPrimaryLocation[2]).ToString() 
	
    Write-Host "Microsoft Azure Services for"$response.Id -ForegroundColor Yellow
    Get-AzureService | Select ServiceName, Url, Location
    
    $a=0
    Do {
        $a++
        Write-Progress -Activity "Working on provisioning $VMInstanceName..." `
            -PercentComplete $a -CurrentOperation "$a% complete" -Status "Please wait."

    	$return = Get-AzureRemoteDesktopFile -Name $VMInstanceName -LocalPath "$RDPPath\$VMInstanceName.rdp" -ServiceName $ServiceName -Launch
    } Until ((Get-AzureVM -ServiceName $ServiceName -Name $VMInstanceName).InstanceStatus -ne 'ReadyRole')

}
#endregion

#region New-PsOpenConnectFlashArrayIscsiSetup
function New-OpenConnectFlashArrayIscsiSetup() {
    [CmdletBinding()]
    Param (
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $ConfigurationFile,
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $VolumeName,
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $VolumeSize,
		[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $HostName
)

	if((Get-WindowsFeature -Name 'Multipath-IO' ).InstallState -eq "Installed") {
		$Creds = Get-Credential
	
		[xml]$xml = Get-Content $ConfigurationFile
		$FAExtMgmt = $xml.OpenConnectMicrosoftAzure.FlashArrayConfiguration.Management.External.vir0
		$Port1 = $xml.OpenConnectMicrosoftAzure.FlashArrayConfiguration.Management.iSCSI.Port1
		$Port2 = $xml.OpenConnectMicrosoftAzure.FlashArrayConfiguration.Management.iSCSI.Port2
		$Port3 = $xml.OpenConnectMicrosoftAzure.FlashArrayConfiguration.Management.iSCSI.Port3
		$Port4 = $xml.OpenConnectMicrosoftAzure.FlashArrayConfiguration.Management.iSCSI.Port4
	
	
		$FlashArray = New-PfaArray -EndPoint $FAExtMgmt -Credentials $Creds -IgnoreCertificateError
		New-PfaHost -Array $FlashArray -IqnList (Get-InitiatorPort).NodeAddress -Name $HostName
		New-PfaVolume -Array $FlashArray -VolumeName $VolumeName -Size $VolumeSize -Unit MB
		New-PfaHostVolumeConnection -Array $FlashArray -VolumeName $VolumeName -HostName $HostName
	
		New-MSDSMSupportedHW -VendorId 'PURE' -ProductId 'FlashArray'	
		#Set-NetAdapterAdvancedProperty -DisplayName 'Jumbo Packet' -RegistryKeyword '*JumboPacket' -RegistryValue 9014
		Set-Service -Name MSiSCSI -StartupType Automatic
		Start-Service -Name MSiSCSI
		New-IscsiTargetPortal -TargetPortalAddress $Port1
		New-IscsiTargetPortal -TargetPortalAddress $Port2
		New-IscsiTargetPortal -TargetPortalAddress $Port3
		New-IscsiTargetPortal -TargetPortalAddress $Port4

		$NetworkAdpater = Get-NetIPAddress –AddressFamily IPv4
		Get-IscsiTarget | Connect-IscsiTarget -IsPersistent $True -IsMultipathEnabled $True -InitiatorPortalAddress $NetworkAdpater[0].IPv4Address
		Enable-MSDSMAutomaticClaim -BusType iSCSI
		Set-MSDSMGlobalDefaultLoadBalancePolicy -Policy RR
	}
	else {
		Write-Error "Please add the Mulitpath-IO Windows Feature using Add-WindowsFeature -Name Multipath-IO and rerun New-OpenConnectFlashArrayiSCSISetup."
	}
}
#endregion

Export-ModuleMember -function New-OpenConnectConfiguration
Export-ModuleMember -function Update-OpenConnectConfiguration
Export-ModuleMember -function Remove-OpenConnectConfiguration
Export-ModuleMember -function New-OpenConnectExpressRoute
Export-ModuleMember -function Update-OpenConnectExpressRoute
Export-ModuleMember -function Remove-OpenConnectExpressRoute
Export-ModuleMember -function New-OpenConnectFlashArrayIscsiSetup
Export-ModuleMember -function New-OpenConnectTestVM