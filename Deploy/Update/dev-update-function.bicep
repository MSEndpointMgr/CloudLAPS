// Define parameters
@description('Provide the name of the existing Function App that was given when CloudLAPS was initially deployed.')
param FunctionAppName string
@description('Provide the name of the existing Log Analytics workspace that was given when CloudLAPS was initially deployed.')
param LogAnalyticsWorkspaceName string
@description('Provide the name of the existing Key Vault that was given when CloudLAPS was initially deployed.')
param KeyVaultName string
@description('Provide the name of the existing Storage Account that was automatically given when CloudLAPS was initially deployed.')
param StorageAccountName string
@description('Provide the number of days when password rotation is allowed. Default is 3.')
param UpdateFrequencyDays string = '3'

// Automatically construct variable for Application Insights based on Function App name input
var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'

// Define existing resources based on param input
resource FunctionApp 'Microsoft.Web/sites@2020-12-01' existing = { 
  name: FunctionAppName
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

// Collect Log Analytics workspace properties to be added to Key Vault as secrets
var LogAnalyticsWorkspaceId = LogAnalyticsWorkspace.properties.customerId
var LogAnalyticsWorkspaceSharedKey = LogAnalyticsWorkspace.listKeys().primarySharedKey

// Construct secrets in Key Vault
resource WorkspaceIdSecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
  name: '${KeyVaultName}/LogAnalyticsWorkspaceId'
  properties: {
    value: LogAnalyticsWorkspaceId
  }
}
resource SharedKeySecret 'Microsoft.KeyVault/vaults/secrets@2019-09-01' = {
  name: '${KeyVaultName}/LogAnalyticsWorkspaceSharedKey'
  properties: {
    value: LogAnalyticsWorkspaceSharedKey
  }
}

// Construct appSettings resource and ensure default values including new ones are added
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
    PasswordLength: '16'
    PasswordAllowedCharacters: 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789'
    LogAnalyticsWorkspaceId: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=LogAnalyticsWorkspaceId)'
    LogAnalyticsWorkspaceSharedKey: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=LogAnalyticsWorkspaceSharedKey)'
    LogTypeClient: 'CloudLAPSClient'
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
