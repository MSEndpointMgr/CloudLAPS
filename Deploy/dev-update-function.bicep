// Define parameters
@description('Provide the name of the existing Function App that was given when CloudLAPS was initially deployed.')
param FunctionAppName string

resource FunctionApp 'Microsoft.Web/sites@2020-12-01' existing = { 
  name: FunctionAppName
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/CloudLAPS/blob/main/Releases/Dev/CloudLAPS-FunctionApp1.1.0.zip'
  }
}
