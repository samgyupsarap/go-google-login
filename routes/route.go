package routes

import (
	"go-google-login/controllers"
	"go-google-login/middleware"
	"net/http"

 	"github.com/gorilla/mux"
)

func SetupRoutes() *mux.Router {
	r := mux.NewRouter()
	userRoutes := r.PathPrefix("/api").Subrouter()

	userController := &controllers.UserController{}
	cookieController := &controllers.CookieController{}
	loginController := &controllers.GoogleLoginController{}
	logoutController := &controllers.LogoutController{}
	bearerMiddleware := &middleware.Middleware{}

	userRoutes.Handle("/users", bearerMiddleware.BearerTokenAuth(http.HandlerFunc(userController.GetAllUsers))).Methods("GET")
	userRoutes.Handle("/user_profile", bearerMiddleware.BearerTokenAuth(http.HandlerFunc(userController.GetUserByID))).Methods("GET")
	userRoutes.HandleFunc("/get_cookie", cookieController.GetCookie).Methods("GET")
	userRoutes.HandleFunc("/delete_cookie", cookieController.DeleteCookie).Methods("POST")
	userRoutes.HandleFunc("/login", loginController.GoogleHandleLogin)
	userRoutes.HandleFunc("/callback-gl", loginController.HandleCallback)
	userRoutes.HandleFunc("/logout", logoutController.LogoutHandler)

	return r
}

