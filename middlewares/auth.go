package auth

import (
    "net/http"
    "github.com/alexedwards/scs/v2"
    "github.com/unrolled/render"
    "log"
)

var rend = render.New(
    render.Options{
        Directory:  "templates",
        Extensions: []string{".tmpl", ".html"},
    })


func AuthMiddleware(SessionManager *scs.SessionManager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Check if user is authenticated
            authenticated := SessionManager.GetBool(r.Context(), "authenticated")
            if !authenticated {
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

//TODO: Destroy session after redirecting to a 404 if role is correct: current walk-around /logout to destroy session
func CheckUserRole(SessionManager *scs.SessionManager, allowedRoles ...uint) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if !SessionManager.Exists(r.Context(), "userID") {
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
            }

            roleIDInterface := SessionManager.Get(r.Context(), "knownRoleId")
            if roleIDInterface == nil {
                http.Redirect(w, r, "/logout", http.StatusSeeOther)
                return
            }

            userRoleID, ok := roleIDInterface.(uint)
            if !ok {
                http.Error(w, "Invalid role format in session", http.StatusInternalServerError)
                return
            }

            for _, allowed := range allowedRoles {
                if userRoleID == allowed {
                    next.ServeHTTP(w, r)
                    return
                }
            }
            
            //http.Error(w, "Forbidden", http.StatusForbidden)
            // Destroy the session first
			err := SessionManager.Destroy(r.Context())
			if err != nil {
			    http.Error(w, "Failed to destroy session", http.StatusInternalServerError)
			    return
			}

            rend.HTML(w, http.StatusForbidden, "error403Page", nil)
        })
    }
}

func Recoverer(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                log.Printf("panic: %v", err)
                rend.HTML(w, http.StatusInternalServerError, "error500Page", nil)
            }
        }()
        next.ServeHTTP(w, r)
    })
}