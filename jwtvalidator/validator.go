package jwtvalidator

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func validateToken(tokenString string, jwksCache *JWKSCache) (*jwt.Token, error) {
	// Parse the token without validation to get the kid from the header
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	keyId, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid not found in token header")
	}
	// Get the public key using the kid
	pubKey, ok := jwksCache.GetJWKS(keyId)
	if !ok {
		return nil, fmt.Errorf("failed to get public key for kid: %s", keyId)
	}

	// Parse and validate the token
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token, nil

}

func validateIssuerAndAudience(token *jwt.Token, expectedIssuer string, expectedAudiences []string) error {
	audience, err := token.Claims.GetAudience()
	if err != nil {
		fmt.Printf("Failed to get audience: %v\n", err)
		return err
	}

	if len(audience) <= 0 || !contains(expectedAudiences, audience[0]) {
		return fmt.Errorf("failed to validate audience")
	}

	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		fmt.Printf("Failed to get issuer: %v\n", err)
		return err
	}

	if len(issuer) <= 0 && strings.Contains(issuer, expectedIssuer) {
		return fmt.Errorf("failed to validate issuer")
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func Authenticate(jwksCache *JWKSCache, tokenString, expectedIssuer string, expectedAudiences []string) bool {
	token, err := validateToken(tokenString, jwksCache)
	if err != nil {
		fmt.Printf("Token validation failed: %v\n", err)
		return false
	} else {
		fmt.Println("Token validated successfully")
	}

	err = validateIssuerAndAudience(token, expectedIssuer, expectedAudiences)
	if err != nil {
		fmt.Printf("Issuer and audience validation failed: %v\n", err)
		return false
	} else {
		fmt.Println("Issuer and audience validated successfully")
	}
	return true
}
