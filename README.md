# Reporting Services Custom Authentication using Azure AD Redirect
Sample code redirects a login from Reporting Services to Azure AD for authentication.

## Step 1: Create Azure AD Application Registrations

### App Registration 1: Reporting Services
Primary application configured for redirect authentication. This is the application where roles and user or group assignments would be configured.

Create a new app registration in your tenant:
1. Under authentication, Set the redirect URL to https://[ssrs server].[ssrs domain]/ReportServer/Login.aspx
1. Under certificates and secrets, create a secet key and note the value for later
1. Under expose and API, add a scope with a name of user_impersonation

Finally, define one or more roles to assign to users as required. The example below defines two roles for common departments.

```json
	"appRoles": [
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "A",
			"displayName": "Human Resources Department Report Access",
			"id": "00000000-0000-0000-0000-000000000001",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "HumanResources"
		},
		{
			"allowedMemberTypes": [
				"User"
			],
			"description": "Accounting Department Report Access",
			"displayName": "System Administrator Role",
			"id": "00000000-0000-0000-0000-000000000002",
			"isEnabled": true,
			"lang": null,
			"origin": "Application",
			"value": "Accounting"
		}
```

### App Registration 2: Reporting Services API
A secondary application to implement the resource owner grant flow in instances where passing username/password is required. An example would be publishing RS reports from visual studio. Roles and user assignments should not be required for this app	.

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

## Step 2: Add SQL Server Objects
Run the script TokenCacheSQLObjects.sql, located in the setup folder, against the ReportServer database.

## Step 3: Configure Reporting Services
### Copy Required Files
#### Copy DLLs
Compile the project and copy the required dll's into the bin folder for RS.

Default directory is: C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin
* Microsoft.Graph.dll
* Microsoft.Graph.Core.dll
* Microsoft.IdentityModel.Clients.ActiveDirectory.dll
* Microsoft.IdentityModel.JsonWebTokens.dll
* Microsoft.IdentityModel.Logging.dll
* Microsoft.IdentityModel.Protocols.dll
* Microsoft.IdentityModel.Protocols.OpenIdConnect.dll
* Microsoft.IdentityModel.Tokens.dll
* RSWebAuthentication.dll
* System.IdentityModel.Tokens.Jwt.dll

#### Copy Login.aspx
Copy Login.aspx from the compiled project into the ReportServer directoy

Default directory is: C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin

### Modify Configuration Files
#### Modify RSReportServer.config
Default location: C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer

Merge the below xml into the RSReportServer.config file after adding a valid machine key and setting your Azure AD user id into the security override section.

```xml
<Configuration>
	<MachineKey ValidationKey="" DecryptionKey="" Validation="SHA1" Decryption="AES"/>
	<UI>
		<ReportServerUrl></ReportServerUrl>
		<PageCountMode>Estimate</PageCountMode>
		<CustomAuthenticationUI>
			<PassThroughCookies>
				<PassThroughCookie>sqlAuthCookie</PassThroughCookie>
			</PassThroughCookies>
		</CustomAuthenticationUI>
	</UI>
	<Extensions>
		<Security>
			<Extension Name="Forms" Type="RSWebAuthentication.TokenAuthorization, RSWebAuthentication">
				<Configuration>
					<AllowedSecurityTypes>
						<Roles/>
					</AllowedSecurityTypes>
					<SecurityOverride>
						<Users>
							<User>[ADUser]@[ADTenant]</User>
							</Users>
						<Roles/>
					</SecurityOverride>
				</Configuration>
			</Extension>
		</Security>
		<Authentication>
			<Extension Name="Forms" Type="RSWebAuthentication.AuthenticationExtension, RSWebAuthentication">
				<Configuration>
					<AllowedSecurityTypes>
						<Roles/>
					</AllowedSecurityTypes>
				</Configuration>
			</Extension>
		</Authentication>
	</Extensions>
</Configuration>
```

#### Modify RSSrvPolicy.config
Default location: C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer

Merge the below xml into the RSSrvPolicy.config file.
```xml
<configuration>
  <mscorlib>
    <security>
      <policy>
        <PolicyLevel version="1">
          <CodeGroup class="FirstMatchCodeGroup" version="1" PermissionSetName="Nothing">
            <CodeGroup class="FirstMatchCodeGroup" version="1" PermissionSetName="Execution" Description="This code group grants MyComputer code Execution permission. ">
              <CodeGroup class="UnionCodeGroup" version="1" Name="SecurityExtensionCodeGroup" Description="Code group for the AAD Authentication" PermissionSetName="FullTrust">
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\RSWebAuthentication.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\Microsoft.IdentityModel.Clients.ActiveDirectory.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\System.IdentityModel.Tokens.Jwt.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\Microsoft.IdentityModel.Tokens.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\Microsoft.IdentityModel.Logging.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\Microsoft.IdentityModel.JsonWebTokens.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\Microsoft.IdentityModel.Protocols.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\Microsoft.IdentityModel.Protocols.OpenIdConnect.dll" />
                <IMembershipCondition class="UrlMembershipCondition" version="1" Url="C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer\bin\Newtonsoft.Json.dll" />
              </CodeGroup>
            </CodeGroup>
          </CodeGroup>
        </PolicyLevel>
      </policy>
    </security>
  </mscorlib>
</configuration>
```

#### Modify Web.config
Default location: C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\ReportServer

Merge the below the below xml into the web.config file after adding a valid machine key and setting correct values in the app settings section.
```xml
<configuration>
  <system.web>
    <authentication mode="Forms">
      <forms loginUrl="Login.aspx" name="sqlAuthCookie" timeout="60" path="/">
      </forms>
    </authentication>
    <authorization>
      <deny users="?" />
    </authorization>
    <identity impersonate="false" />
    <securityPolicy>
      <trustLevel name="RosettaSrv" policyFile="rssrvpolicy.config" />
    </securityPolicy>
    <trust level="Full" originUrl="" legacyCasModel="true" />
    <machineKey validationKey="" decryptionKey="" validation="SHA1" decryption="AES" />
  </system.web>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-12.0.0.0" newVersion="12.0.0.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <appSettings>
    <add key="TenantId" value="" />
    <add key="ClientID" value="" />
    <add key="ClientSecret" value="" />
    <add key="RedirectURI" value="https://[servername].[domain]/ReportServer/Login.aspx" />
    <add key="AuthorizeURI" value="https://login.microsoftonline.com/[TenantId]/oauth2/v2.0/Authorize" />
    <add key="AuthorityURI" value="https://login.microsoftonline.com/[TenantId]" />
    <add key="APIClientId" value="" />
    <add key="APIResource" value="" />
    <add key="TokenCacheSqlConnectionString" value="Server=.;Database=ReportServer;Trusted_Connection=True" />
  </appSettings>
</configuration>
```

#### Modify RSPortal.config
Default location: C:\Program Files\Microsoft SQL Server Reporting Services\SSRS\Portal

Merge the below xml into the RSPortal.config file after setting correct values in the app settings section.
```xml
<configuration>
  <appSettings>
    <add key="TenantId" value="" />
    <add key="ClientID" value="" />
    <add key="ClientSecret" value="" />
    <add key="RedirectURI" value="https://[servername].[domain]/ReportServer/Login.aspx" />
    <add key="AuthorizeURI" value="https://login.microsoftonline.com/[TenantId]/oauth2/v2.0/Authorize" />
    <add key="AuthorityURI" value="https://login.microsoftonline.com/[TenantId]" />
    <add key="APIClientId" value="" />
    <add key="APIResource" value="" />
    <add key="TokenCacheSqlConnectionString" value="Server=.;Database=ReportServer;Trusted_Connection=True" />
  </appSettings>
</configuration>
```

## Step 4: Verification and Usage
Start RS services and verify redirect.

The user (or role) configured in the <SecurityOverride> section of the RSReportServer.config will have full rights to the report server.

If the config for <AllowedSecurityTypes> was left with the default <Roles/>, any role added to the app manifest can be mapped to a reporting services role through the web GUI.
* When assigning an app manifest role, the name must match the app manifest role's "value".
* Users or groups assigned to the app role in Azure AD will gain all RS role permissions assigned to the app role.

