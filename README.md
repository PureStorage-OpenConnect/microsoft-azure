#Pure Storage<sup>&reg;</sup> Open Connect for Microsoft Azure

The Open Connect for Microsoft Azure PowerShell module can be used by Pure Storage customers and partners looking at integrating Microsoft Azure on-premise or with a Cloud Exchange Provider.<br>

The PowerShell module encapsulates Azure, ExpressRoute and Pure Storage PowerShell cmdlets to simplify deployment of Azure ExpressRoute, creating test virtual machines and applying best practices for Pure Storage iSCSI configurations on Windows Server.<br>

The following PowerShell cmdlets are provided within the module:<br>

* New-OpenConnectConfiguration
* Update-OpenConnectConfiguration
* Remove-OpenConnectConfiguration
* New-OpenConnectExpressRoute
* Update-OpenConnectExpressRoute
* Remove-OpenConnectExpressRoute
* New-OpenConnectFlashArrayIscsiSetup
* New-OpenConnectTestVM

The above cmdlets encapsulate both Azure PowerShell and Pure Storage PowerShell SDK cmdlets to make the process of creating an Azure ExpressRoute connection, deploying a virtual machine and connecting to a Pure Storage FlashArray straightforward and simple.<br>

Please use the [Issues](https://github.com/PureStorage-OpenConnect/MicrosoftAzure/issues) section to enter your questions, comments or feature requests.<br>

All releases of the PowerShellToolkit will have a digitally signed MSI.<br>
