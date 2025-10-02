module main

go 1.24.2

replace models => ./models

replace db => ./db

replace middlewares/auth => ./middlewares

replace routes => ./routes

replace routes/routes => ./routes

require (
	db v0.0.0-00010101000000-000000000000
	github.com/alexedwards/scs/mysqlstore v0.0.0-20250417082927-ab20b3feb5e9
	github.com/alexedwards/scs/v2 v2.8.0
	middlewares/auth v0.0.0-00010101000000-000000000000
	routes/routes v0.0.0-00010101000000-000000000000
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-chi/chi/v5 v5.2.2 // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/richardlehane/mscfb v1.0.4 // indirect
	github.com/richardlehane/msoleps v1.0.4 // indirect
	github.com/tiendc/go-deepcopy v1.6.0 // indirect
	github.com/unrolled/render v1.7.0 // indirect
	github.com/xuri/efp v0.0.1 // indirect
	github.com/xuri/excelize/v2 v2.9.1 // indirect
	github.com/xuri/nfp v0.0.1 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/net v0.40.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df // indirect
	gorm.io/driver/mysql v1.6.0 // indirect
	gorm.io/gorm v1.30.0 // indirect
	handlers/handlers v0.0.0-00010101000000-000000000000 // indirect
	models v0.0.0-00010101000000-000000000000 // indirect
)

replace handlers/handlers => ./handlers
