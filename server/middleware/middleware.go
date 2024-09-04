package middleware

import (
	"Golang-Csrf/db"
	myJwt "Golang-Csrf/server/middleware/myJwt"
	"log"
	"net/http"
	"strings"
	"time"
	"github.com/justinas/alice"
)

func NewHandler() http.Handler{
	return alice.New(recoverHandler,authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler{
//helps to recover in case of panic error. it gives 500 error.
//the system won't crash,itwill be handled.
	fn := func(w http.ResponseWriter,r *http.Request){
		defer func(){
			if err:= recover();err!=nil{
				log.Panic("Recovered from Panic! - %+v",err)
				http.Error(w,http.StatusText(500),500);
			}
		}()

		next.ServeHTTP(w,r);
	}

	return http.HandlerFunc(fn);
}

func authHandler(next http.Handler) http.Handler{
	fn := func (w http.ResponseWriter,r *http.Request)  {

		switch r.URL.Path{
		case "/restricted","/logout","/deleteUser"://check jwt token

		default:
		}
		
	}
	return http.HandlerFunc(fn);
}


//storing the tokens in cookies.
func setAuthAndRefreshCookies(w *http.ResponseWriter,authTokenString string,refreshTokenString string){
	authCookie := http.Cookie{
		Name:"AuthToken",
		Value:authTokenString,
		HttpOnly:true,
		Secure: true,
	}

	authCookie.SameSite=http.SameSiteLaxMode;

	http.SetCookie(*w,&authCookie);

	refreshCookie := http.Cookie{
		Name:"RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
		Secure: true,
	}

	refreshCookie.SameSite=http.SameSiteLaxMode;

	http.SetCookie(*w,&refreshCookie);


}

func grabCsrfFromReq(w http.ResponseWriter,r *http.Request)string{
	csrfFrom := r.FormValue("X-CSRF-Token");

	if csrfFrom!=""{
		return csrfFrom;
	}else{
		return r.Header.Get("X-CSRF-Token");
	}
}


//revokes the cookies.
func nullifyTokenCookies(w *http.ResponseWriter,r *http.Request){
	authCookie := http.Cookie{
		Name:"AuthToken",
		Value: "",
		Expires: time.Now().Add(100*time.Hour),
		HttpOnly: true,
		 Secure: true,
	}

	http.SetCookie(*w,&authCookie);


	refreshCookie := http.Cookie{
		Name:"RefreshToken",
		Value: "",
		Expires: time.Now().Add(130*time.Hour),
		HttpOnly: true,
		Secure: true,
	};

	http.SetCookie(*w,&refreshCookie);

	RefreshCookie,err := r.Cookie("RefreshToken")

	if err==http.ErrNoCookie{
		return;
	}else if err!=nil{
		log.Panic("panic: %+v",err.Error());
		http.Error(*w,http.StatusText(500),500);
	}

	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func logicHandler(w http.ResponseWriter,r *http.Request){
	switch r.URL.Path{
	case "/restricted":

	case "/login":
		switch r.Method{
		case "GET":
		case "POST":
		default:
		}
	
	case "/register":
		switch r.Method{
			case "GET":
			case "POST":
			default:
		}
	
	case "/logout":
	case "/deleteUser":

	default:


	}
}