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

type Tracks struct {
    ID int `gorm:"primaryKey"`
    TrackTitle string
    ArtistName string
    TrackCode string
    Genre string
    TrackPath string
    Featured bool `gorm:"default:false"`
    TrackAvatar string
    gorm.Model
}

type SessionIdResponse struct {
    ID int `gorm:"primaryKey"`
    RequestRefId string
    ResponseMessage string
    CustomerMessage string
    SessionID string
    RedirectURL string
    Product string
    ProductType string
    ProductCode string
    ProductDetails string
    gorm.Model
}