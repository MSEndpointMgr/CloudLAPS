// Define parameters
@description('Provide the name of the existing Function App that was given when CloudLAPS was initially deployed.')
param FunctionAppName string
@description('Provide the name of the existing Function App that was given when CloudLAPS was initially deployed.')
param LogAnalyticsWorkspaceName string

resource FunctionApp 'Microsoft.Web/sites@2020-12-01' existing = { 
  name: FunctionAppName
}

resource LogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2020-10-01' existing = {
  name: LogAnalyticsWorkspaceName
}

var FunctionAppCurrentSettings = list('${FunctionApp.name}/appSettings', '2020-12-01').properties

//resource FunctionAppSettings 'Microsoft.Web/sites/config@2020-06-01' = {
//  name: '${FunctionApp.name}/appsettings'
//  properties: {
//    WorkspaceId: LogAnalyticsWorkspace.properties.customerId
//    SharedKey: LogAnalyticsWorkspace.listKeys().primarySharedKey
//    LogType: 'CloudLAPSClient'
//  }
//}

resource FunctionAppSettings 'Microsoft.Web/sites/config@2020-06-01' = {
  name: '${FunctionApp.name}/appsettings'
  properties: union(FunctionAppCurrentSettings, {
    WorkspaceId: LogAnalyticsWorkspace.properties.customerId
    SharedKey: LogAnalyticsWorkspace.listKeys().primarySharedKey
    LogType: 'CloudLAPSClient'
  })
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/releases/download/dev/CloudLAPS-FunctionApp1.1.0.zip'
  }
}
