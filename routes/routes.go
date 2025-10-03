package routes

import (
	"net/http"
	"middlewares/auth"
	"handlers/handlers"	
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"
	"github.com/alexedwards/scs/v2"
	"github.com/unrolled/render"
)



func Routes(db *gorm.DB, SessionManager *scs.SessionManager) http.Handler {
	//public routes
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(middleware.CleanPath)

	h := &handlers.Handler{DB: db, SessionManager: SessionManager,}
	router.Use(SessionManager.LoadAndSave)
	router.Get("/", h.HomeHandler)
	router.Post("/", h.HomeHandler)

	//auth routes
	router.Get("/login", h.LoginHandler)
	router.Post("/login", h.LoginHandler)
	router.Get("/signup", h.SignupHandler)
	router.Post("/signup", h.SignupHandler)
	router.Get("/logout", h.LogoutHandler)
	router.Get("/forgot", h.ForgotHandler)
	router.Post("/forgot", h.ForgotHandler)
	router.Get("/resetpassword", h.ResetPasswordHandler)
	router.Post("/resetpassword", h.ResetPasswordHandler)



	var rend = render.New(
	render.Options{
		Directory:  "templates",
		Extensions: []string{".tmpl", ".html"},
	})


	//admin routes
	router.Group(func(router chi.Router) {
		router.Use(auth.AuthMiddleware(SessionManager))
		router.Use(auth.CheckUserRole(SessionManager, 1))
		router.Get("/admin", h.AdminDashHandler)
		router.Get("/admin/create", h.AdminCreateHandler)
		router.Post("/admin/create", h.AdminCreateHandler)
	})


	//error pages
	//404
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
	    rend.HTML(w, http.StatusNotFound, "error404Page", nil)
	})

	//405
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
	    rend.HTML(w, http.StatusMethodNotAllowed, "error405Page", nil)
	})



	//static
	fs := http.FileServer(http.Dir("./static"))
	uploads :=  http.FileServer(http.Dir("./media"))
	templ := http.FileServer(http.Dir("./templates"))
	router.Handle("/static/*", http.StripPrefix("/static/", fs))
	router.Handle("/media/*", http.StripPrefix("/media/", uploads))
	router.Handle("/templates/*", http.StripPrefix("/templates/", templ))
	return router
}
