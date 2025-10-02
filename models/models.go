 package models

import (
	"gorm.io/gorm"
    "time"
)

type User struct {
	ID 			uint `gorm:"primaryKey"`
	Username 	string `gorm:"unique"`
    RoleId      uint
    Role        Role  
    Email       string `gorm:"unique"`
    FirstName   string
    LastName    string
    Password    string
    Avatar      string  `gorm:"default:'default-avatar.jpg'"`
    gorm.Model
}

type Role struct {
	ID 			 uint `gorm:"primaryKey"`
	RoleName 	string `gorm:"unique"`
    gorm.Model 
}

type Session struct {
    ID uint `gorm:"primaryKey"`
    Token string
    Data []byte     `gorm:"type:blob"`
    Expiry time.Time
}

