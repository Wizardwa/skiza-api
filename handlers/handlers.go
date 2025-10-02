package handlers

import (
	"fmt"
	_"html/template"
	_ "middlewares/auth"
	"models"
	"net/http"
	"regexp"
	"github.com/alexedwards/scs/v2"
	"github.com/unrolled/render"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"encoding/json"
	"log"
	"encoding/base64"
	"gopkg.in/gomail.v2"
	"crypto/tls"
	_"io"
	_"os"
	_"path/filepath"
	_"github.com/go-chi/chi/v5"
	_"strconv"
	_"strings"
	_"bytes"
	_"crypto/hmac"
	_"crypto/sha256"
	_"encoding/hex"
	_"errors"
	_"net/url"
	_"sort"
	_"time"
	_"math/rand"
	_"encoding/csv"
	_"github.com/xuri/excelize/v2"
)

var rend = render.New(
	render.Options{
		Directory:  "templates",
		Extensions: []string{".tmpl", ".html"},
	})

const uploadPath = "./media"

type Handler struct {
	DB             *gorm.DB
	SessionManager *scs.SessionManager
	Rend *render.Render
	ApiKey         string
	ApiUrl         string
}


type ForgotUser struct {
	Name string  `json:"username"`
	Email string `json:"email"`
}


//index
func (h *Handler) HomeHandler(w http.ResponseWriter, r *http.Request) {
	rend.HTML(w, http.StatusOK, "indexPage", nil)
}


//admin
func(h *Handler) AdminDashHandler(w http.ResponseWriter, r *http.Request) {
	rend.HTML(w, http.StatusOK, "adminAnalyticsPage", nil)
}

func (h *Handler) AdminCreateHandler(w http.ResponseWriter, r *http.Request) {
	rend.HTML(w, http.StatusOK, "adminCreatePage",nil)
}


//auth
func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	//bcrypt.CompareHashAndPassword(hashedPassword, password)
	var user models.User
	if r.Method == http.MethodPost {

		//process form
		if err := r.ParseForm(); err != nil {
			fmt.Printf("ParseForm error: %v\n", err)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		//parse values
		emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
		check := emailRegex.MatchString(email)
		if check {
			//check if user exists

			result := h.DB.Where("email = ?", email).First(&user)
			if result.Error != nil {
				fmt.Println("Username does not exist")
			} else {
				err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
				if err != nil {
					fmt.Println("Wrong password")
				} else {
					h.SessionManager.Put(r.Context(), "userID", user.Username)
					h.SessionManager.Put(r.Context(), "knownRoleId", user.RoleId)
					h.SessionManager.Put(r.Context(), "authenticated", true)

					//check role id and redirect
					http.Redirect(w,r, "/admin", http.StatusSeeOther)
			        return 
				}
			}

		} else {
			fmt.Println("Invalid email!!")
		}

	}
	rend.HTML(w, http.StatusOK, "loginPage", nil)
}

func (h *Handler) SignupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		//parse form
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		email := r.FormValue("email")
		firstName := r.FormValue("firstname")
		lastName := r.FormValue("lastname")
		password := r.FormValue("password")

		if username == "" || email == "" || password == "" {
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
		if !emailRegex.MatchString(email) {
			http.Error(w, "Invalid email format", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Could not hash password", http.StatusInternalServerError)
			return
		}

		user := models.User{
			Username:  username,
			Email:     email,
			FirstName: firstName,
			LastName:  lastName,
			Password:  string(hashedPassword),
			RoleId:    2,
		}

		if err := h.DB.Create(&user).Error; err != nil {
			fmt.Println("Failed to create account!")
			http.Redirect(w, r, "/signup", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	
	rend.HTML(w, http.StatusOK, "signupPage", nil)
}

func SendTicketMail(h *Handler,recipient,emailContent,subject string) error {
	// SMTP server configuration
	smtpHost := "mail.radiaperlmantechnologies.com"
	smtpPort := 587
	senderEmail := "davis.ewaat@radiaperlmantechnologies.com"
	senderPassword := "qPAcLygG7s9c3TUS3tPf"


	m := gomail.NewMessage()
	m.SetHeader("From", senderEmail)
	m.SetHeader("To", recipient)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", emailContent)

	// Create a dialer that understands port 465 (SMTPS)
	d := gomail.NewDialer(smtpHost, smtpPort, senderEmail, senderPassword)
	d.TLSConfig = &tls.Config{
	    InsecureSkipVerify: true,
	}


	// Send the email
	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("could not send email: %w", err)
		fmt.Println(err)
	}

	log.Printf("Mail sent successfully to %s", recipient)
	return nil
}


func (h *Handler) ForgotHandler(w http.ResponseWriter, r *http.Request) {
	//forgot password
	if r.Method == http.MethodPost {
		//check if user exists
		var user models.User

		email := r.FormValue("email")

		emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
		check := emailRegex.MatchString(email)
		if check {
			//check if user exists

			result := h.DB.Where("email = ?", email).First(&user)
			if result.Error != nil {
				fmt.Println("Email does not exist")
			} else {
				//construct reset link
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}

				host := r.Host
				baseUrl := fmt.Sprintf("%s://%s", scheme, host)
				forgot := ForgotUser{
					Name: user.Username,
					Email: user.Email,
				}
				jsonData, err := json.Marshal(forgot)
				if err != nil {
					fmt.Println("Error: Unable to marshal json object for forgot")
				}

				encodeValue := base64.StdEncoding.EncodeToString([]byte(jsonData))
				//doubleEncode := base64.StdEncoding.EncodeToString([]byte(encodeValue))
				fullUrl := baseUrl + "/resetpassword" + "?" + "data=" + encodeValue
				
				//send mail
				recipient := user.Email
				subject := "Reset Password"
				emailContent := "Open this link to reset your password " + fullUrl
				SendTicketMail(h,recipient, emailContent, subject)
				
			}

		} else {
			fmt.Println("Invalid email!!")
		}

	}
	rend.HTML(w, http.StatusOK, "forgotPage", nil)
}

func (h *Handler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		data := r.FormValue("data")

		if password == confirmPassword {
			//decode data
			decodeString, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				fmt.Println("Failed to decode base64 from the data!")
			}
			var forgot ForgotUser
			err = json.Unmarshal(decodeString, &forgot)
			if err != nil {
				fmt.Println("Failed to Unmarshal forgot user data!")
			}

			//TODO: parse email
			var user models.User

			result := h.DB.Where("email = ?", forgot.Email).First(&user)
			if result.Error != nil {
				fmt.Println("User does not exist!")
			}else{
				//set new password
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					fmt.Println("Failed to hash password!")
				}
				//update password
				userUpdate := models.User{
					Password:  string(hashedPassword),
				}
				if err := h.DB.Model(&userUpdate).Where("email = ?", forgot.Email).Updates(&userUpdate).Error; err != nil {
					fmt.Println("Failed to update password!")
				}
				http.Redirect(w,r,"/login", http.StatusSeeOther)
				return

			}

		}

	}
	rend.HTML(w, http.StatusOK, "resetPage", nil)
}



func (h *Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	//destroy session
	h.SessionManager.Destroy(r.Context())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
