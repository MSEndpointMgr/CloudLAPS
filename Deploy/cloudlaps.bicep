// Define parameters
@description('Provide the App registration application identifier.')
param ApplicationID string
@description('Provide a name for the Function App that consists of alphanumerics. Name must be globally unique and cannot start or end with a hyphen.')
param FunctionAppName string
@allowed([
    'Y1'
    'EP1'
    'EP2'
    'EP3'
])
@description('Select the desired App Service Plan of the Function App. Select Y1 for free consumption based deployment.')
param FunctionAppServicePlanSKU string = 'EP1'
@description('Provide a name for the portal website that consists of alphanumerics. Name must be globally unique and cannot start or end with a hyphen.')
param PortalWebAppName string
@allowed([
  'F1'
  'D1'
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
@description('Select the desired App Service Plan for the portal website. Select B1, D1 or F1 SKUs for minimum cost. Recommended SKU for optimal performance and cost is S1.')
param PortalAppServicePlanSKU string = 'S1'
@description('Provide a name for the Key Vault. Name must be a 3-24 character string, containing only 0-9, a-z, A-Z, and - characters.')
param KeyVaultName string
@description('Provide a name for the Log Analytics workspace.')
param LogAnalyticsWorkspaceName string
@description('Provide any tags required by your organization (optional)')
param Tags object = {}

// Define variables
var UniqueString = uniqueString(resourceGroup().id)
var FunctionAppNameNoDash = replace(FunctionAppName, '-', '')
var PortalWebAppNameNoDash = replace(PortalWebAppName, '-', '')
var StorageAccountName = toLower('${take(FunctionAppNameNoDash, 17)}${take(UniqueString, 5)}sa')
var FunctionAppServicePlanName = '${FunctionAppName}-fa-plan'
var PortalAppServicePlanName = toLower('${PortalWebAppName}-wa-plan')
var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'
var PortalAppInsightsName = '${FunctionAppName}-wa-ai'

// Create storage account for Function App
resource storageaccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: StorageAccountName
  location: resourceGroup().location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties:{
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: true
  }
  tags: Tags
}

// Create app service plan for Function App
resource appserviceplan 'Microsoft.Web/serverfarms@2021-01-15' = {
  name: FunctionAppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  sku: {
    name: FunctionAppServicePlanSKU
  }
  tags: Tags
}

// Create application insights for Function App
resource FunctionAppInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' = {
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
    serverFarmId: appserviceplan.id
    containerSize: 1536
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      powerShellVersion: '~7'
      scmType: 'None'
      appSettings: [
        {
          name: 'AzureWebJobsDashboard'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
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
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'UpdateFrequencyDays'
          value: '3'
        }
        {
          name: 'KeyVaultName'
          value: KeyVaultName
        }
      ]
    }
  }
  tags: Tags
}

// Create Log Analytics workspace
resource LogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2020-10-01' = {
  name: LogAnalyticsWorkspaceName
  location: resourceGroup().location
  properties: {
    sku: {
      name: 'Free'
    }
  }
}

// Create app service plan for CloudLAPS portal
resource AppServicePlan 'Microsoft.Web/serverfarms@2021-01-15' = {
  name: PortalAppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  sku: {
    name: PortalAppServicePlanSKU
  }
  tags: Tags
}

// Create application insights for CloudLAPS portal
resource PortalAppInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' = {
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
resource PortalAppService 'Microsoft.Web/sites@2020-06-01' = {
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

// Create Key Vault
resource KeyVault 'Microsoft.KeyVault/vaults@2019-09-01' = {
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

// Deploy application settings for CloudLAPS Portal
resource PortalAppServiceAppSettings 'Microsoft.Web/sites/config@2020-06-01' = {
  name: '${PortalAppService.name}/appsettings'
  properties: {
      // Add three settings to enable storing of funcitons keys in keyvault
      AzureWebJobsSecretStorageKeyVaultName: KeyVault.name
      APPLICATIONINSIGHTS_CONNECTION_STRING: reference(PortalAppInsightsComponents.id, '2020-02-02-preview').ConnectionString
      APPINSIGHTS_INSTRUMENTATIONKEY: reference(PortalAppInsightsComponents.id, '2020-02-02-preview').InstrumentationKey
      'AzureAd:TenantId': subscription().tenantId
      'AzureAd:ClientId': ApplicationID
      'KeyVault:Uri': KeyVault.properties.vaultUri
      'LogAnalytics:WorkspaceId': LogAnalyticsWorkspace.properties.customerId
      'LogAnalytics:SharedKey': LogAnalyticsWorkspace.listKeys().primarySharedKey
      'LogAnalytics:LogType': 'CloudLAPSAudit'
  }
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
    parent: FunctionApp
    name: 'ZipDeploy'
    properties: {
        packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/1.0.0/CloudLAPS-FunctionApp1.0.0.zip'
    }
}

// Add ZipDeploy for CloudLAPS Portal
resource PortalZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: PortalAppService
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/1.0.0/CloudLAPS-Portal1.0.0.zip'
  }
}
