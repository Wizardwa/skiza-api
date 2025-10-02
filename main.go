package main

import (
	"fmt"
	"net/http"
	"routes/routes"
	_"middlewares/auth"
	"db"
	"time"
    "github.com/alexedwards/scs/v2"
    "github.com/alexedwards/scs/mysqlstore"
	
)

var SessionManager *scs.SessionManager

func main() {

	db := db.Init()

	//session management
	SessionManager = scs.New()
    SessionManager.Lifetime = 24 * time.Hour
    SessionManager.Cookie.Secure = false
    SessionManager.Cookie.SameSite = http.SameSiteStrictMode

    sqlDB, err := db.DB()
	if err != nil {
		fmt.Println("Error getting *sql.DB:", err)
		return
	}

    SessionManager.Store = mysqlstore.New(sqlDB)
    mysqlstore.NewWithCleanupInterval(sqlDB, 30 * time.Minute)

	fmt.Println("Server started at 7000 ...")
	err = http.ListenAndServe(":7000", routes.Routes(db, SessionManager))
	if err != nil {
	    fmt.Println("Failed to start server:", err)
	}

}
