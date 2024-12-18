# JWT Validator

This project is a simple JWT (JSON Web Token) validator. It verifies the integrity and authenticity of JWT token. This project is tested for Azure AD and can be used for other Auth2 providers. 

## Features

- Validate JWT tokens - Tested for Azure AD
- Validated the Audience and Issuer.
- Caches the JWT key and refresh in regular interval

## Test

### Clone Repo
```bash
git clone https://github.com/yourusername/jwtvalidator.git
cd jwtvalidator
go mod tidy
```

### Generate token
1. Create an Azure AD Application
2. Create secret for the Azure AD Application
3. Generate token. Replace the `<tenant-id>`, `<client-id>` and `client-secret`
```
curl --location 'https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=client_credentials' \
--data-urlencode 'scope=<client-id>/.default' \
--data-urlencode 'client_id=<client-id>' \
--data-urlencode 'client_secret=<client-secret>'
```
4. Update the `expectedIssuer=<tenant-id>`, `expectedAudiences=<client-id>` and `tokenString=<token>` in [main.go](./main.go)
5. Test
```
go run main.do
```

