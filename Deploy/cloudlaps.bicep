// Define parameters
@description('Provide the App registration application identifier.')
param ApplicationID string
@description('Provide a name for the Function App that consists of alphanumerics. Name must be globally unique in Azure and cannot start or end with a hyphen.')
param FunctionAppName string
@allowed([
  'Y1'
  'EP1'
  'EP2'
  'EP3'
])
@description('Select the desired App Service Plan of the Function App. Select Y1 for free consumption based deployment.')
param FunctionAppServicePlanSKU string = 'EP1'
@description('Provide a name for the portal website that consists of alphanumerics. Name must be globally unique in Azure and cannot start or end with a hyphen.')
param PortalWebAppName string
@allowed([
  'B1'
  'P1V2'
  'P1V3'
  'P2V2'
  'P2V3'
  'P3V2'
  'P3V3'
  'S1'
  'S2'
  'S3'
  'P1'
  'P2'
  'P3'
])
@description('Select the desired App Service Plan for the portal website. Select B1, SKU for minimum cost. Recommended SKU for optimal performance and cost is S1.')
param PortalAppServicePlanSKU string = 'S1'
@minLength(3)
@maxLength(24)
@description('Provide a name for the Key Vault. Name must be globally unique in Azure and between 3-24 characters, containing only 0-9, a-z, A-Z, and - characters.')
param KeyVaultName string
@description('Provide a name for the Log Analytics workspace.')
param LogAnalyticsWorkspaceName string
@description('Provide any tags required by your organization (optional)')
param Tags object = {}

// Define variables
var UniqueString = uniqueString(resourceGroup().id)
var FunctionAppNameNoDash = replace(FunctionAppName, '-', '')
var FunctionAppNameNoDashUnderScore = replace(FunctionAppNameNoDash, '_', '')
var PortalWebAppNameNoDash = replace(PortalWebAppName, '-', '')
var StorageAccountName = toLower('${take(FunctionAppNameNoDashUnderScore, 17)}${take(UniqueString, 5)}sa')
var FunctionAppServicePlanName = '${FunctionAppName}-fa-plan'
var PortalAppServicePlanName = toLower('${PortalWebAppName}-wa-plan')
var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'
var PortalAppInsightsName = '${FunctionAppName}-wa-ai'
var KeyVaultAppSettingsName = '${take(KeyVaultName, 21)}-as'

// Create storage account for Function App
resource StorageAccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: StorageAccountName
  location: resourceGroup().location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: true
  }
  tags: Tags
}

// Create app service plan for Function App
resource FunctionAppServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: FunctionAppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  sku: {
    name: FunctionAppServicePlanSKU
  }
  properties: {}
  tags: Tags
}

// Create application insights for Function App
resource FunctionAppInsightsComponents 'Microsoft.Insights/components@2020-02-02' = {
  name: FunctionAppInsightsName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
  tags: union(Tags, {
    'hidden-link:${resourceId('Microsoft.Web/sites', FunctionAppInsightsName)}': 'Resource'
  })
}

// Create function app
resource FunctionApp 'Microsoft.Web/sites@2020-12-01' = {
  name: FunctionAppName
  location: resourceGroup().location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: FunctionAppServicePlan.id
    containerSize: 1536
    httpsOnly: true
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      powerShellVersion: '~7'
      scmType: 'None'
      appSettings: [
        {
          name: 'AzureWebJobsDashboard'
          value: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower('CloudLAPS')
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
        {
          name: 'AzureWebJobsDisableHomepage'
          value: 'true'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~3'
        }
        {
          name: 'FUNCTIONS_WORKER_PROCESS_COUNT'
          value: '3'
        }
        {
          name: 'PSWorkerInProcConcurrencyUpperBound'
          value: '10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02').InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02').ConnectionString
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
      ]
    }
  }
  tags: Tags
}

// Create Log Analytics workspace
resource LogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2021-06-01' = {
  name: LogAnalyticsWorkspaceName
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
  }
}

// Create app service plan for CloudLAPS portal
resource AppServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: PortalAppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  sku: {
    name: PortalAppServicePlanSKU
  }
  properties: {}
  tags: Tags
}

// Create application insights for CloudLAPS portal
resource PortalAppInsightsComponents 'Microsoft.Insights/components@2020-02-02' = {
  name: PortalAppInsightsName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
  tags: union(Tags, {
    'hidden-link:${resourceId('Microsoft.Web/sites', PortalWebAppName)}': 'Resource'
  })
}

// Create app service for CloudLAPS portal
resource PortalAppService 'Microsoft.Web/sites@2022-03-01' = {
  name: PortalWebAppNameNoDash
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: AppServicePlan.id
    siteConfig: {
      alwaysOn: true
      metadata: [
        {
          name: 'CURRENT_STACK'
          value: 'dotnetcore'
        }
      ]
    }
  }
}

// Create Key Vault for local admin passwords
resource KeyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: KeyVaultName
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
            'set'
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

// Create Key Vault for Function App application settings
resource KeyVaultAppSettings 'Microsoft.KeyVault/vaults@2022-07-01' = {
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

// Collect Log Analytics workspace properties to be added to Key Vault as secrets
var LogAnalyticsWorkspaceId = LogAnalyticsWorkspace.properties.customerId
var LogAnalyticsWorkspaceSharedKey = LogAnalyticsWorkspace.listKeys().primarySharedKey

// Construct secrets in Key Vault
resource WorkspaceIdSecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  name: '${KeyVaultAppSettingsName}/LogAnalyticsWorkspaceId'
  properties: {
    value: LogAnalyticsWorkspaceId
  }
  dependsOn: [
    KeyVaultAppSettings
  ]
}
resource SharedKeySecret 'Microsoft.KeyVault/vaults/secrets@2022-07-01' = {
  name: '${KeyVaultAppSettingsName}/LogAnalyticsWorkspaceSharedKey'
  properties: {
    value: LogAnalyticsWorkspaceSharedKey
  }
  dependsOn: [
    KeyVaultAppSettings
  ]
}

// Deploy application settings for CloudLAPS Function App
resource FunctionAppSettings 'Microsoft.Web/sites/config@2022-03-01' = {
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
    APPINSIGHTS_INSTRUMENTATIONKEY: reference(FunctionAppInsightsComponents.id, '2020-02-02').InstrumentationKey
    APPLICATIONINSIGHTS_CONNECTION_STRING: reference(FunctionAppInsightsComponents.id, '2020-02-02').ConnectionString
    FUNCTIONS_WORKER_RUNTIME: 'powershell'
    UpdateFrequencyDays: '3'
    KeyVaultName: KeyVaultName
    DebugLogging: 'False'
    PasswordLength: '16'
    PasswordAllowedCharacters: 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz.:;,-_!?$%*=+&<>@#()23456789'
    LogAnalyticsWorkspaceId: '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceId)'
    LogAnalyticsWorkspaceSharedKey: '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceSharedKey)'
    LogTypeClient: 'CloudLAPSClient'
  }
  dependsOn: [
    FunctionAppZipDeploy
  ]
}

// Deploy application settings for CloudLAPS Portal
resource PortalAppServiceAppSettings 'Microsoft.Web/sites/config@2022-03-01' = {
  name: '${PortalAppService.name}/appsettings'
  properties: {
      AzureWebJobsSecretStorageKeyVaultName: KeyVault.name
      APPLICATIONINSIGHTS_CONNECTION_STRING: reference(PortalAppInsightsComponents.id, '2020-02-02').ConnectionString
      APPINSIGHTS_INSTRUMENTATIONKEY: reference(PortalAppInsightsComponents.id, '2020-02-02').InstrumentationKey
      'AzureAd:TenantId': subscription().tenantId
      'AzureAd:ClientId': ApplicationID
      'KeyVault:Uri': KeyVault.properties.vaultUri
      'LogAnalytics:WorkspaceId': '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceId)'
      'LogAnalytics:SharedKey': '@Microsoft.KeyVault(VaultName=${KeyVaultAppSettingsName};SecretName=LogAnalyticsWorkspaceSharedKey)'
      'LogAnalytics:LogType': 'CloudLAPSAudit'
  }
  dependsOn: [
    PortalZipDeploy
  ]
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
    parent: FunctionApp
    name: 'ZipDeploy'
    properties: {
        packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/1.1.0/CloudLAPS-FunctionApp1.1.0.zip'
    }
}

// Add ZipDeploy for CloudLAPS Portal
resource PortalZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: PortalAppService
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/1.1.0/CloudLAPS-Portal1.1.0.zip'
  }
}
