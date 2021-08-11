// Define parameters
param FunctionAppName string
@allowed([
    'Y1'
    'EP1'
    'EP2'
    'EP3'
])
param FunctionAppType string = 'EP1'
param KeyVaultName string
param Tags object = {}

// Define variables
var UniqueString = uniqueString(resourceGroup().id)
var FunctionAppNameNoDash = replace(FunctionAppName, '-', '')
var StorageAccountName = toLower('${take(FunctionAppNameNoDash, 17)}${take(UniqueString, 5)}sa')
var AppServicePlanName = '${FunctionAppName}-Plan'

// Create storage account for function app
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

// Create app service plan
resource appserviceplan 'Microsoft.Web/serverfarms@2021-01-15' = {
  name: AppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  sku: {
    name: FunctionAppType
  }
  tags: Tags
}

// Create application insights
resource appInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' = {
  name: FunctionAppName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
  tags: union(Tags, {
    'hidden-link:${resourceId('Microsoft.Web/sites', FunctionAppName)}': 'Resource'
  })
}


// Create function app
resource azureFunction 'Microsoft.Web/sites@2020-12-01' = {
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
          value: reference(appInsightsComponents.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: reference(appInsightsComponents.id, '2020-02-02-preview').ConnectionString
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
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/1.0.0/CloudLAPS-FunctionApp1.0.0.zip'
        }
      ]
    }
  }
  tags: Tags
}

// Create Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2019-09-01' = {
  name: KeyVaultName
  location: resourceGroup().location
  properties: {
    enabledForDeployment: false
    enabledForTemplateDeployment: false
    enabledForDiskEncryption: false
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        tenantId: azureFunction.identity.tenantId
        objectId: azureFunction.identity.principalId
        permissions: {
          secrets: [
            'get'
            'set'
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
