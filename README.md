
__The Open Connect for Microsoft Azure PowerShell module has been deprecated. The project remaains as a reference.__

---
# Pure Storage Open Connect for Microsoft Azure

The Open Connect for Microsoft Azure PowerShell module can be used by Pure Storage customers and partners looking at integrating Microsoft Azure on premises or with a Cloud Exchange Provider.

The PowerShell module encapsulates Azure, ExpressRoute and Pure Storage PowerShell cmdlets to simplify deployment of Azure ExpressRoute, creating test virtual machines and applying best practices for Pure Storage iSCSI configurations on Windows Server.

The following PowerShell cmdlets are provided within the module:

* New-OpenConnectConfiguration
* Update-OpenConnectConfiguration
* Remove-OpenConnectConfiguration
* New-OpenConnectExpressRoute
* Update-OpenConnectExpressRoute
* Remove-OpenConnectExpressRoute
* New-OpenConnectFlashArrayIscsiSetup
* New-OpenConnectTestVM

The above cmdlets encapsulate both Azure PowerShell and Pure Storage PowerShell SDK cmdlets to make the process of creating an Azure ExpressRoute connection, deploying a virtual machine and connecting to a Pure Storage FlashArray straightforward and simple.

Please use the [Issues](https://github.com/PureStorage-OpenConnect/MicrosoftAzure/issues) section to enter your questions, comments or feature requests.

All releases of the PowerShellToolkit will have a digitally signed MSI.
