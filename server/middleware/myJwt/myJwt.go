package myJwt

import (
	"crypto/rsa"
	"io/ioutil"
	"time"
	"errors"
	"log"
	jwt "github.com/dgrijalva/jwt-go"
	models "Golang-Csrf/models"
	db "Golang-Csrf/db"
)

const (
	privateKeyPath = "keys/app.rsa";
	publicKeyPath = "keys/app.rsa.pub";
)

func InitJWT()error{

}

func CreateNewTokens()(){}

func CheckAndRefreshTokens()(){

}

func createAuthTokenString()(){

}

func createRefreshTokenString()(){

}

func updateRefreshTokenExpire()(){

}

func updateAuthTokenString()(){

}

func RevokeRefreshToken()error{

}

func updateRefreshTokenCsrf()(){

}

func GrabUUID()(){
	
}