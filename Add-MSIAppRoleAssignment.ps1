# Assign static variables
$TenantID = "<Enter Tenant ID>"
$MSIObjectID = "<Enter Managed System Identity Object ID>"

# Authenticate against Azure AD, as Global Administrator
Connect-AzureAD -TenantId $TenantID

$MSGraphAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph (graph.microsoft.com) application ID
$MSGraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$($MSGraphAppId)'"
$RoleNames = @("Device.Read.All")

# Assign each roles to Managed System Identity, first validate they exist
foreach ($RoleName in $RoleNames) {
    $AppRole = $MSGraphServicePrincipal.AppRoles | Where-Object { $PSItem.Value -eq $RoleName -and $PSItem.AllowedMemberTypes -contains "Application" }
    if ($AppRole -ne $null) {
        New-AzureAdServiceAppRoleAssignment -ObjectId $MSIObjectID -PrincipalId $MSIObjectID -ResourceId $MSGraphServicePrincipal.ObjectId -Id $AppRole.Id
    }
}