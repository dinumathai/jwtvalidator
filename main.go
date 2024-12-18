package main

import (
	"time"

	"github.com/dinumathai/jwtvalidator/jwtvalidator"
)

func main() {
	wellKnownURL := "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
	tokenString := ``
	expectedAudiences := []string{""}
	expectedIssuer := ""

	jwksCache := jwtvalidator.NewJWKSCache(wellKnownURL, 30*time.Second)
	defer jwksCache.Stop()

	jwtvalidator.Authenticate(jwksCache, tokenString, expectedIssuer, expectedAudiences)
}
