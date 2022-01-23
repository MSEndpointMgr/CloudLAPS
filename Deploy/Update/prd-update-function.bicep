// Define parameters
@description('Provide the name of the existing Function App that was given when CloudLAPS was initially deployed.')
param FunctionAppName string
@description('Provide the name of the existing portal Web App that was given when CloudLAPS was initially deployed.')
param PortalWebAppName string
@description('Provide the name of the existing Log Analytics workspace that was given when CloudLAPS was initially deployed.')
param LogAnalyticsWorkspaceName string
@description('Provide the name of the existing Key Vault that was given when CloudLAPS was initially deployed.')
param KeyVaultName string
@description('Provide the name of the existing Storage Account that was automatically given when CloudLAPS was initially deployed.')
param StorageAccountName string
@description('Provide the App registration application identifier that was created when CloudLAPS was initially deployed.')
param ApplicationID string
@description('Provide the number of days when password rotation is allowed. Default is 3.')
param UpdateFrequencyDays string = '3'
@description('Provide the default length of the generated local admin password. Default is 16.')
param PasswordLength string = '16'
@description('Provide the default character set to be used when generating the local admin password. Default is value is ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789.')
param PasswordAllowedCharacters string = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789'

// Automatically construct variables based on param input
var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'
var PortalAppInsightsName = '${FunctionAppName}-wa-ai'
var KeyVaultAppSettingsName = '${take(KeyVaultName, 21)}-as'

// Define existing resources based on param input
resource FunctionApp 'Microsoft.Web/sites@2020-12-01' existing = { 
  name: FunctionAppName
}
resource PortalAppService 'Microsoft.Web/sites@2020-12-01' existing = { 
  name: PortalWebAppName
}
resource LogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2020-10-01' existing = {
  name: LogAnalyticsWorkspaceName
}
resource KeyVault 'Microsoft.KeyVault/vaults@2019-09-01' existing = {
  name: KeyVaultName
}
resource StorageAccount 'Microsoft.Storage/storageAccounts@2021-06-01' existing = {
  name: StorageAccountName
}
resource FunctionAppInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' existing = {
  name: FunctionAppInsightsName
}
resource PortalAppInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' existing = {
  name: PortalAppInsightsName
}

// Collect Log Analytics workspace properties to be added to Key Vault as secrets
var LogAnalyticsWorkspaceId = LogAnalyticsWorkspace.properties.customerId
var LogAnalyticsWorkspaceSharedKey = LogAnalyticsWorkspace.listKeys().primarySharedKey

// Remove trailing forward slash from Key Vault uri property
var KeyVaultUri = KeyVault.properties.vaultUri
var KeyVaultUriNoSlash = substring(KeyVaultUri, 0, length(KeyVaultUri)-1)

// Create Key Vault for Function App application settings
resource KeyVaultAppSettings 'Microsoft.KeyVault/vaults@2019-09-01' = {
  name: KeyVaultAppSettingsName
  location: resourceGroup().location
  properties: {
    enabledForDeployment: false
    enabledForTemplateDeployment: false
    enabledForDiskEncryption: false
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        tenantId: FunctionApp.identity.tenantId
        objectId: FunctionApp.identity.principalId
        permissions: {
          secrets: [
            'get'
          ]
        }
      }
      {
        tenantId: PortalAppService.identity.tenantId
        objectId: PortalAppService.identity.principalId
        permissions: {
          secrets: [
            'get'
          ]
        }
      }
    ]
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
}

// Construct secrets in Key Vault
resource WorkspaceIdSecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
  name: '${KeyVaultAppSettingsName}/LogAnalyticsWorkspaceId'
  properties: {
    value: LogAnalyticsWorkspaceId
  }
  dependsOn: [
    KeyVaultAppSettings
  ]
}
resource SharedKeySecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
  name: '${KeyVaultAppSettingsName}/LogAnalyticsWorkspaceSharedKey'
  properties: {
    value: LogAnalyticsWorkspaceSharedKey
  }
  dependsOn: [
    KeyVaultAppSettings
  ]
}

// Construct appSettings resource for Function App and ensure default values including new ones are added
resource FunctionAppSettings 'Microsoft.Web/sites/config@2020-06-01' = {
  name: '${FunctionApp.name}/appsettings'
  properties: {
    AzureWebJobsDashboard: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
    AzureWebJobsStorage: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
    WEBSITE_CONTENTAZUREFILECONNECTIONSTRING: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
    WEBSITE_CONTENTSHARE: toLower('CloudLAPS')
    WEBSITE_RUN_FROM_PACKAGE: '1'
    AzureWebJobsDisableHomepage: 'true'
    FUNCTIONS_EXTENSION_VERSION: '~3'
    FUNCTIONS_WORKER_PROCESS_COUNT: '3'
    PSWorkerInProcConcurrencyUpperBound: '10'
    APPINSIGHTS_INSTRUMENTATIONKEY: reference(FunctionAppInsightsComponents.id, '2020-02-02-preview').InstrumentationKey
    APPLICATIONINSIGHTS_CONNECTION_STRING: reference(FunctionAppInsightsComponents.id, '2020-02-02-preview').ConnectionString
    FUNCTIONS_WORKER_RUNTIME: 'powershell'
    UpdateFrequencyDays: UpdateFrequencyDays
    KeyVaultName: KeyVaultName
    DebugLogging: 'False'
    PasswordLength: PasswordLength
    PasswordAllowedCharacters: PasswordAllowedCharacters
    LogAnalyticsWorkspaceId: '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceId)'
    LogAnalyticsWorkspaceSharedKey: '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceSharedKey)'
    LogTypeClient: 'CloudLAPSClient'
  }
}

// Construct appSettings resource for CloudLAPS Portal and ensure default values including new ones are added
resource PortalAppServiceAppSettings 'Microsoft.Web/sites/config@2020-06-01' = {
  name: '${PortalAppService.name}/appsettings'
  properties: {
      AzureWebJobsSecretStorageKeyVaultName: KeyVault.name
      APPLICATIONINSIGHTS_CONNECTION_STRING: reference(PortalAppInsightsComponents.id, '2020-02-02-preview').ConnectionString
      APPINSIGHTS_INSTRUMENTATIONKEY: reference(PortalAppInsightsComponents.id, '2020-02-02-preview').InstrumentationKey
      'AzureAd:TenantId': subscription().tenantId
      'AzureAd:ClientId': ApplicationID
      'KeyVault:Uri': KeyVaultUriNoSlash
      'LogAnalytics:WorkspaceId': '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceId)'
      'LogAnalytics:SharedKey': '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceSharedKey)'
      'LogAnalytics:LogType': 'CloudLAPSAudit'
  }
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/1.1.0/CloudLAPS-FunctionApp1.1.0.zip'
  }
}
