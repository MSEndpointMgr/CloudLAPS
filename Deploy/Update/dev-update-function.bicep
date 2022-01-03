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

var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'

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
    WorkspaceId: LogAnalyticsWorkspace.properties.customerId
    SharedKey: LogAnalyticsWorkspace.listKeys().primarySharedKey
    LogType: 'CloudLAPSClient'
  }
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/dev/CloudLAPS-FunctionApp1.1.0.zip'
  }
}
