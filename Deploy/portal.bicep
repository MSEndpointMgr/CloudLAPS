// Define parameters
param WebAppName string
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
param AppServicePlanSKU string = 'S1'
param Tags object = {}

// Define variables
var AppServicePlanName = toLower('${WebAppName}-plan')
var WebSiteName = toLower('${WebAppName}-webapp')

// Create app service plan
resource AppServicePlan 'Microsoft.Web/serverfarms@2021-01-15' = {
  name: AppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  sku: {
    name: AppServicePlanSKU
  }
  tags: Tags
}

// Create application insights
resource appInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' = {
  name: WebAppName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
  tags: union(Tags, {
    'hidden-link:${resourceId('Microsoft.Web/sites', WebAppName)}': 'Resource'
  })
}

// Create app service
resource AppService 'Microsoft.Web/sites@2020-06-01' = {
  name: WebSiteName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: AppServicePlan.id
    siteConfig: {
      netFrameworkVersion: 'v5.0'
      alwaysOn: true
    }
  }
}
