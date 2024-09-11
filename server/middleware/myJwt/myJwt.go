package myJwt

import (
	models "Golang-Csrf/db/model"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	db "Golang-Csrf/db"
)

const (
	privateKeyPath = "keys/id_rsa.rsa"
	publicKeyPath  = "keys/id_rsa.rsa.pub"
)

var signKeyGlobal *rsa.PrivateKey
var verifyKeyGlobal *rsa.PublicKey

func InitJWT() error {
	signBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		log.Println("Wrong in InitJWT-1");

		return err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)

	if err != nil {
		log.Println("Wrong in InitJWT-2");
		log.Println(err);

		
	}

	//read public key
	verifyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		log.Println("Wrong in InitJWT-3");

		return err
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		log.Println("Wrong in InitJWT-4");

		return err
	}

	verifyKeyGlobal = verifyKey
	signKeyGlobal = signKey

	return nil
}

func CreateNewTokens(uuid string, role string) (authTokenString string, refreshTokenString string, csrfSecret string, err error) {
	//generate csrf secret
	csrfSecret, err = models.GenerateCSRFSecret()

	if err != nil {
		log.Println("Wrong in CreateNewTokens-1");

		return "", "", "", err
	}
	//generate refresh token
	refreshToken, err := createRefreshTokenString(uuid, role, csrfSecret)

	if err != nil {
		log.Println("Wrong in CreateNewTokens-2");

		return "", "", "", err
	}

	//generate auth token
	authToken, err := createAuthTokenString(uuid, role, csrfSecret)

	if err != nil {
		log.Println("Wrong in CreateNewTokens-3");

		return "", "", "", err
	}

	return authToken, refreshToken, csrfSecret, nil

}

func CheckAndRefreshTokens(oldAuthTokenString string,
	oldRefreshTokenString string,
	oldCsrfSecret string) (newAuthToken string,
	newRefreshToken string,
	newCsrfToken string,
	err error) {

	if oldCsrfSecret == "" {
		log.Println("No CSRF token in CheckAndRefreshTokens!")
		err = errors.New("Unauthorized")
		return "","","",err;
	}

	if(oldAuthTokenString==""){
		log.Println("No Auth Token string in CheckAndRefreshTokens!");
		err   = errors.New("Unauthorized. As the auth Token is empty!");
		return "","","",err;
	}

	if(oldRefreshTokenString==""){
		log.Println("No Refresh Token string in CheckAndRefreshTokens!");
		err = errors.New("Unauthorized . As the refreshToken is empty!");
		return "","","",err;
	}

	autToken, err := jwt.ParseWithClaims(oldAuthTokenString,
		&models.TokenClaims{},
		func(t *jwt.Token) (interface{}, error) {
			return verifyKeyGlobal, nil
		})

	if err != nil {
		log.Println("Something went wrong during parsing token of auth in CheckAndRefreshTokens!");
		log.Println(err)
		return "","","",err;
	}

	authTokenClaims, ok := autToken.Claims.(*models.TokenClaims)
	// jwt.NewWithClaims(jwt.GetSigningMethod("RSA256"), authClaims)

	if !ok {
		log.Println("CheckAndRefreshTokens error")
		return "","","",errors.New("token claims for auth token could not be created!");
	}

	if oldCsrfSecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return "","","",err;
	}

	if autToken.Valid {
		log.Println("Auth token is valid")

		newCsrfSecretGenerated := authTokenClaims.Csrf
		newRefreshTokenString, err := updateRefreshTokenExpire(oldRefreshTokenString)

		newAuthTokenString := oldAuthTokenString
		return newAuthTokenString,newRefreshTokenString,newCsrfSecretGenerated,err;
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		log.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			log.Println("Auth token is expired ")
			newAuthToken1, newCsrfSecret, err2 := updateAuthTokenString(oldAuthTokenString, oldRefreshTokenString)

			if err2 != nil {
				return "","","",err;
			}

			newRefreshTokenString, err := updateRefreshTokenExpire(oldRefreshTokenString)

			if err != nil {
				return "","","",err;
			}

			newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			return newAuthToken1,newRefreshTokenString,newCsrfSecret,nil;
		} else {
			log.Println("Error in auth token!")
			err = errors.New("Error in auth token")
			return"","","",err;
		}
	}else {
		log.Println("Error in auth token")
		err = errors.New("Error in auth token!")
		return "","","",err;
	}

	err = errors.New("Unauthorized")
	return "","","",err;
}

func updateRefreshTokenCsrf(oldRefreshTokenString string,
	newCsrfTokenString string)(string,error){
		refreshToken,err := jwt.ParseWithClaims(oldRefreshTokenString,&models.TokenClaims{},func(token *jwt.Token)(interface{},error){
			return verifyKeyGlobal,nil
		})

		if err!=nil{
			log.Println("Some thing went wrong updateRefreshTokenCsrf,while parsing claims!");
			return "",err;
		}

		oldRefreshTokenClaims,ok := refreshToken.Claims.(*models.TokenClaims);

		if !ok{
			log.Println("Something went wrong in updateRefreshTokenCsrf!");
			return "",errors.New("Failed to fetch refresh token claims!");
		}

		refreshClaims := models.TokenClaims{
			jwt.StandardClaims{
				Id:oldRefreshTokenClaims.StandardClaims.Id,
				Subject:oldRefreshTokenClaims.StandardClaims.Subject,
				ExpiresAt:oldRefreshTokenClaims.StandardClaims.ExpiresAt,
			},
			oldRefreshTokenClaims.Role,
			newCsrfTokenString,
		}

		//new refresh token
		refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),refreshClaims);

		newRefreshTokenString,err := refreshJwt.SignedString(signKeyGlobal);

		if err!=nil{
			log.Println("Some thing went wrong in updateRefreshTokenCsrf while generating new refrsh token")
			return "",err;
		}
		return newRefreshTokenString,nil;
}

func createAuthTokenString(uuid string, role string, csrfSecret string) (authToken string, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		role,
		csrfSecret,
	}

	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RSA256"), authClaims)
	authTokenString, err := authJwt.SignedString(signKeyGlobal)

	if err != nil {
		fmt.Println("Try again ,something went wrong while creating auth thoken")
		return "", err
	}

	return authTokenString, nil
}

func createRefreshTokenString(uuid string, role string, csrfSecret string) (refreshToken string, err error) {
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	refreshJti, err := db.StoreRefreshToken()

	if err != nil {
		return "", err
	}

	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   uuid,
			ExpiresAt: refreshTokenExp,
		},
		role,
		csrfSecret,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshToken, err = refreshJwt.SignedString(signKeyGlobal)

	if err != nil {
		return "", nil
	}

	return refreshToken, nil
}

func updateRefreshTokenExpire(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKeyGlobal, nil
	})

	if err!=nil{
		log.Println("Something went wrong in updateRefreshTokenExpire-1");
		return "",err;
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok {
		return "",errors.New("Something went wrong in updateRefreshTokenExpire-2")
	}

	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		 oldRefreshTokenClaims.Role,
		 oldRefreshTokenClaims.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKeyGlobal)

	if err!=nil{
		log.Println("Something went wrong in updateRefreshTokenExpire-3")
		return "",err;
	}

	return newRefreshTokenString,nil;
}

func updateAuthTokenString(refreshTokenString string,
	 oldAuthTokenString string) (newAuthToken string,
		 csrfSecret string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKeyGlobal, nil
	})

	if err!=nil{
		log.Println("Something went wrong in updateAuthTokenString-1")
		return "","",err;
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok {
		log.Println("something went wrong in updateAuthTokenString-3")
		return "", "", errors.New("Error reading jwt claims!")
	}

	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {
		if refreshToken.Valid {
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKeyGlobal, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)

			if !ok {
				log.Println("something went wrong in updateAuthTokenString-2")
				err = errors.New("Error reading jwt claims2!")

				return "", "", err
			}

			csrfSecret, err := models.GenerateCSRFSecret()

			if err != nil {
				return "", "", err
			}

			newAuthTokenString, err := createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)

			if err!=nil{
				log.Println("updateAuthTokenString- could not create auth token!")
				return "","",err;
			}

			return newAuthTokenString, csrfSecret, nil
		} else {
			log.Println("Refresh token is expired!")
			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

			err = errors.New("Request in unanthorized!")
			log.Println("something went wrong in updateAuthTokenString-4")

			return "", "", err
		}
	} else {
		log.Println("Refresh token has revoked!")
		err = errors.New("Unauthorized!")
		log.Println("something went wrong in updateAuthTokenString-5")

		return "", "", err
	}
}

//deletes refresh token
func RevokeRefreshToken(refreshTokenString string,) error {
	//use refresh token stringget the refresh token
	refreshToken,err := jwt.ParseWithClaims(refreshTokenString,
		&models.TokenClaims{},
		func(token *jwt.Token)(interface{},error){
		return verifyKeyGlobal,nil;
	});

	if err!=nil{
		return errors.New("Could not parse refreshToken with claims!");
	}

	refreshTokenClaims,ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok{
		return errors.New("Could not read refresh token claims!"); 
	}
	//get the claims.

	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

	return nil;

}

func UpdateRefreshTokenCsrf(oldRefreshTokenString string,newCsrfString string)(newRefreshTokenString string,
	err error) {

		//get access to old refresh token
		refreshToken,err := jwt.ParseWithClaims(oldRefreshTokenString,
			&models.TokenClaims{},
			func(token *jwt.Token)(interface{},
				error){return verifyKeyGlobal,nil;},)

		if err!=nil{
			return "",errors.New("Failed to parse the refresh token string while updating RefreshTokenCsrf!");

		}

		// get access to its claims.
		oldRefreshTokenClaims,ok := refreshToken.Claims.(*models.TokenClaims)

		if !ok{
			return "",errors.New("Failed to get the oldRefreshClaims while updating RefreshTokenCsrf!");

		}

		//refreshClaims
		refreshClaims := models.TokenClaims{
			jwt.StandardClaims{
				Id: oldRefreshTokenClaims.StandardClaims.Id,
				Subject:oldRefreshTokenClaims.StandardClaims.Subject,
				ExpiresAt:oldRefreshTokenClaims.StandardClaims.ExpiresAt,
			},
			oldRefreshTokenClaims.Role,
			newCsrfString,
		}
		//new refresh jwt token
		// jwt.NewWithClaims(jwt.GetSigningMethod("RSA256"), authClaims)

		refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"),refreshClaims)
		newRefreshTokenString,err = refreshJwt.SignedString(signKeyGlobal)

		if err!=nil{
			log.Println("UpdateRefreshTokenCsrf->could not create new refresh token!")
			return "",err;
		}
		
		//new token string.
		return newRefreshTokenString,nil;
}

func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return "", errors.New("error fetching claims")
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)

	if !ok {
		return "", errors.New("error fetching claims22")
	}

	return authTokenClaims.StandardClaims.Subject, nil
}
