#
# Module manifest for module 'AADDeviceTrust'
#
# Generated by: Nickolaj Andersen @NickolajA
#
# Generated on: 2022-01-01
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'AADDeviceTrust.psm1'
    
    # Version number of this module.
    ModuleVersion = '1.0.0'
    
    # ID used to uniquely identify this module
    GUID = '52da9652-f13b-47d6-9836-4ecb6d4afb0a'
    
    # Author of this module
    Author = 'Nickolaj Andersen'
    
    # Company or vendor of this module
    CompanyName = 'MSEndpointMgr.com'
    
    # Copyright statement for this module
    Copyright = '(c) 2022 Nickolaj Andersen. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'Provides a set of functions to validate if a request against an API is made by a trusted Azure AD device.'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.0'
    
    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @("")
    
    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @("Get-AzureADDeviceAlternativeSecurityIds",
                          "Get-AzureADDeviceRecord",
                          "New-HashString",
                          "Test-AzureADDeviceAlternativeSecurityIds",
                          "Test-Encryption"
    )
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()
    
            # A URL to the license for this module.
            # LicenseUri = ''
    
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/MSEndpointMgr/AADDeviceTrust'
    
            # A URL to an icon representing this module.
            # IconUri = ''
    
            # ReleaseNotes of this module
            # ReleaseNotes = ''
    
        } # End of PSData hashtable
    
    } # End of PrivateData hashtable
    
    }
    
    