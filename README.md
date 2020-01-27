# Authorize Users in Reporting Services with Azure AD
The sample code leverages Reporting Services' form based authentication extension to redirect usesr to Azure AD for authentication and authorization.



## Step 1: Create Azure AD Application Registrations
Reporting services consists of two main functional components, the API backend and the web interface front end. To fully integrate AAD with RS, two App Registrations were needed:

### App Registration 1: Reporting Services
This will represent the applicaiton web front end. It will also be the only registration requiring user assignment.

Create a new app registration in your tenant:
1. Under authentication, Set the redirect URL to https://[ssrs server].[ssrs domain]/ReportServer/Login.aspx
1. Under certificates and secrets, create a secet key and note the value for later
1. Under expose and API, add a scope with a name of user_impersonation

Finally, replace the default appRoles section in the manifset with the following:

```json
	"appRoles": [
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "View system properties, shared schedules, and allow use of Report Builder or other clients that execute report definitions.",
			"displayName": "System User Role",
			"id": "00000000-0000-0000-0000-000000000001",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "SystemUserRole"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "View and modify system role assignments, system role definitions, system properties, and shared schedules, in addition to create role definitions, and manage jobs in Management Studio.",
			"displayName": "System Administrator Role",
			"id": "00000000-0000-0000-0000-000000000002",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "SystemAdministratorRole"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "May publish reports and linked reports; manage folders, reports, and resources in a users My Reports folder.",
			"displayName": "My Reports Role",
			"id": "00000000-0000-0000-0000-000000000003",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "MyReportsRole"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "May view report definitions.",
			"displayName": "Report Builder Role",
			"id": "00000000-0000-0000-0000-000000000004",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "ReportBuilderRole"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "May view folders, reports, and subscribe to reports.",
			"displayName": "Browser Role",
			"id": "00000000-0000-0000-0000-000000000005",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "BrowserRole"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "May publish reports and linked reports to the Report Server.",
			"displayName": "Publisher Role",
			"id": "00000000-0000-0000-0000-000000000006",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "PublisherRole"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "May manage content in the Report Server. This includes folders, reports, and resources.",
			"displayName": "Content Manager Role",
			"id": "00000000-0000-0000-0000-000000000007",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "ContentManagerRole"
		}
	],
```

### App Registration 2: Reporting Services API
Used to implement the resource owner grant flow in instances where we're connecting directly to the API. An example would be publishing RS reports from visual studio.

Create a new app registration in your tenant:
1. Under Authentication, toggle default client type to Yes.
1. Under API Permissions, click add a permission:
    1. Find the API for app registration 1 under the My APIs tab.
    1. Add select the user_impersonation scope.

### App Registration Final Configuration
1. Return to the app registration 1 configuration:
1. Under expose an API, add a client application.
    1. Add the client ID for app registration 2.
    1. Check the box for authorized scopes (user_impersonation).
    1. Click add application.

## Step 2: Configure Reporting Services
