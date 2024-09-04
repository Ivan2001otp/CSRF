package randomstrings

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomString(size int)(string,error){
	b,err := GenerateRandomBytes(size)
	return base64.RawStdEncoding.EncodeToString(b),err;
}

func GenerateRandomBytes(n int)([]byte,error){
	b:= make([]byte,n);
	_,err := rand.Read(b);
	if err!=nil{
		return nil,err;
	}
	
	return b,nil;
}