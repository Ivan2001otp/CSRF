package middleware

import (
	"Golang-Csrf/db"
	myJwt "Golang-Csrf/server/middleware/myJwt"
	templates "Golang-Csrf/server/templates"
	"log"
	"net/http"
	"strings"
	"time"
	"github.com/justinas/alice"
)

func NewHandler() http.Handler{
	//this helps to chain the mulitple handlers.
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
			log.Println("IN auth restricted section!")

			AuthCookie,authErr := r.Cookie("AuthToken")
			
			if authErr==http.ErrNoCookie{
				log.Println("Unauthorized attempt . No auth Cookie !");
				nullifyTokenCookies(&w,r);
				http.Error(w,http.StatusText(401),401);
				return;
			}else if authErr!=nil{
				log.Panic("panic : %+v",authErr)
				nullifyTokenCookies(&w,r)
				http.Error(w,http.StatusText(500),500);
				return;
			}

			RefreshCookie,refreshErr :=  r.Cookie("RefreshToken")

			if refreshErr==http.ErrNoCookie{
				log.Println("Unauthorized attempt. No refresh Cookie found1");
				nullifyTokenCookies(&w,r);
				http.Redirect(w,r,"/login",302);
				return;
			}else if (refreshErr!=nil){
				log.Panic("panic: %+v",refreshErr);
				nullifyTokenCookies(&w,r);
				http.Error(w,http.StatusText(500),500);
				return;
			}

			requestCsrfToken := grabCsrfFromReq(w,r)
			log.Println(requestCsrfToken)

		    authTokenString,refreshTokenString,csrfSecret,err := myJwt.CheckAndRefreshTokens(AuthCookie.Value,RefreshCookie.Value,requestCsrfToken)

			if err!=nil{
				if err.Error()=="Unauthorized"{
					log.Println("Unauthorized attempt! Jwt are not valid!");
					http.Error(w,http.StatusText(401),401);
					return;
				}else{
					log.Panic("Err not nil");
					log.Panic("panic: %+v",err);
					http.Error(w,http.StatusText(500),500);
					return;
				}
			}
			log.Println("Successfully recreated jwts");

			//cors error
			w.Header().Set("Access-Control-Allow-Origin","*");
			setAuthAndRefreshCookies(&w,authTokenString,refreshTokenString)
			w.Header().Set("X-CSRF-Token",csrfSecret); 
			break;

		default:
			//no check necessary
		}

		next.ServeHTTP(w,r);

		
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
func nullifyTokenCookies(w *http.ResponseWriter,
	r *http.Request){
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
		csrfSecret := grabCsrfFromReq(w,r)
		templates.RenderTemplate(w,"restricted",&templates.RestrictedPage{csrfSecret,"Hello Immanuel!"})
		break;

	case "/login":
		switch r.Method{
		case "GET":
			templates.RenderTemplate(w,"login",&templates.LoginPage{false,""})
			break;

		case "POST":
			r.ParseForm()
			log.Println(r.Form);
			user,uuid,loginErr :=db.LogUserIn(strings.Join(r.Form["username"],""),strings.Join(r.Form["password"],""),)
			log.Println(user,uuid,loginErr);

			if loginErr!=nil{
				w.WriteHeader(http.StatusUnauthorized)
				
			}else{
				authTokenString,refreshTokenString,csrfSecretString,err := myJwt.CreateNewTokens(uuid,user.Role);
				if err!=nil{
					http.Error(w,http.StatusText(500),500);
				}

				setAuthAndRefreshCookies(&w,authTokenString,refreshTokenString);

				w.Header().Set("X-CSRF-Token",csrfSecretString);
				w.WriteHeader(http.StatusOK)
			}

			break;
		
		default:
			w.WriteHeader(http.StatusMovedPermanently);
		}
		
		break;


	case "/register":
		switch r.Method{
			case "GET":
				templates.RenderTemplate(w,"register",&templates.RegisterPage{false,""})
				break;

			case "POST":
				r.ParseForm()
				log.Println(r.Form)
				_,uuid,err	:= db.FetchUserByUsername(strings.Join(r.Form["username"],""))
				
				if err==nil{
					w.WriteHeader(http.StatusUnauthorized)
					return;
				}else{
					role:="user"

					uuid,err = db.StoreUser(
						strings.Join(r.Form["username"],""),
						strings.Join(r.Form["password"],""),
						role)
					 
					if err!=nil{
						http.Error(w,http.StatusText(500),500);
					}
					log.Println("uuid: "+uuid);

				  authTokenString,refreshTokenString,csrfSecret,err :=	myJwt.CreateNewTokens(uuid,role)
					

				  if err!=nil{
					http.Error(w,http.StatusText(500),500)
				  }

				  setAuthAndRefreshCookies(&w,authTokenString,refreshTokenString);
				  w.Header().Set("X-CSRF-Token",csrfSecret)
				  w.WriteHeader(http.StatusOK)
				}

				break;

			default:
				w.WriteHeader(http.StatusMethodNotAllowed)

			break;
		}
	
	case "/logout":
		//remove user's ability to make requestss.
		nullifyTokenCookies(&w,r);
		//use 302,makes the browser to get GET request.
		http.Redirect(w,r,"/login",302)
		break;

	case "/deleteUser":
		log.Println("Deleting User!")

		AuthCookie,authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie{
			log.Println("Unauthorized attempt! No auth cookie");
			nullifyTokenCookies(&w,r);
			http.Redirect(w,r,"/login",302);
			return;
		}else if authErr!=nil{
			log.Panic("panic : %+v",authErr);
			nullifyTokenCookies(&w,r);
			http.Error(w,http.StatusText(500),500);
			return;
		}

		uuid ,uuidErr := myJwt.GrabUUID(AuthCookie.Value);

		if uuidErr!=nil{
			log.Panic("panic : %+v",uuidErr);
			nullifyTokenCookies(&w,r);
			http.Error(w,http.StatusText(500),500);
			return;
		}

		db.DeleteUser(uuid)

		nullifyTokenCookies(&w,r);

		http.Redirect(w,r,"/register",302)
		break;

	default:
		w.WriteHeader(http.StatusOK);

	}
}