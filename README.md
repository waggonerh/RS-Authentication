# RS-Authentication
Custom RS authentication extention. Native forms authentication support is overriden to redirect to AAD for authentication.
* Extension can be installed in an on-premise or cloud hosted VM.

## Business Case
A small/mid sized client requires a low cost paginated report solution hosted in Azure.
### Limitations/Roadblocks
* Power BI Premium supports paginated reports, but is not cost effective.
* SSRS is limited on authentication capabilities, does not support SSO.
* Client lacks existing AD-FS or domain controller vm in Azure.

### Solution Goal
* Authenticate SSRS using AAD token.
* Define all permissions with AAD claims/roles.

## TODO:
* Document SSRS config file changes
* Document how to create AAD app registrations
