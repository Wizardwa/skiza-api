package db

import (
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"models"
	"fmt"
)



func Init() *gorm.DB {
	dsn := "ewaat:cyberwiz@tcp(localhost:3306)/lamahuraan_skiza?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		PrepareStmt: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	err = db.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.Session{},
	)
	if err != nil {
		fmt.Println("Error")	
	}

	roles := []string{"Administrator","Staff"}
	for _, roleName := range roles {
		db.FirstOrCreate(&models.Role{}, models.Role{RoleName: roleName})
	}

	return db
}
