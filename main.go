package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
	"encoding/hex"
  "math/rand"
	"fmt"
	"net/http"
	"path/filepath"
	"github.com/gin-contrib/sessions"
  gormsessions "github.com/gin-contrib/sessions/gorm"
)

type User struct {
	ID       int
	USERNAME string
	EMAIL    string
	PASSWORD string
	PHOTO    string
	UpdatedAt string
	CreatedAt string
}

type Auth struct {
	ID int
	USER_ID int
	TOKEN string
}

type Photo struct {
	ID int
	TITLE string
	CAPTION string
	PHOTO_URL string
	USER_ID int
}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func GenerateSecureToken(length int) string {
    b := make([]byte, length)
    if _, err := rand.Read(b); err != nil {
        return ""
    }
    return hex.EncodeToString(b)
}

func main() {
	db, err := gorm.Open(sqlite.Open("database.db"), &gorm.Config{})
	if err != nil {
    panic(err)
  }
	store := gormsessions.NewStore(db, true, []byte("secret"))
	r := gin.Default()
	r.Use(sessions.Sessions("mysession", store))

	r.POST("/users/register", func(c *gin.Context) {
		username := c.PostForm("username")
		email := c.PostForm("email")
		pwd := c.PostForm("password")

		hashed, _ := HashPassword(pwd)

		user := User{USERNAME: username, EMAIL: email, PASSWORD: hashed, PHOTO: ""}
		if err != nil {
        panic("failed to connect database")
    }
		db.Create(&user)
		c.JSON(200, gin.H{"nama": "hehe"})
	})

	r.POST("/users/signin", func (c *gin.Context)  {
		email := c.PostForm("email")
		pwd := c.PostForm("password")
		session := sessions.Default(c)

		var ath Auth
		var result User

		db.First(&result, "`users`.`email` = ?", email)
		if result == (User{}) {
			c.JSON(404, gin.H{"error": "email tidak ketemu"})
			return
		}

		password := result.PASSWORD

		db.First(&ath, "user_id = ?", result.ID)
		token := GenerateSecureToken(10)
		if ath == (Auth{}) {
			auth := Auth{USER_ID: result.ID, TOKEN: token}
			db.Create(&auth)
		} else {
			ath.TOKEN = token
			db.Save(&ath)
		}

		session.Set("token", token)
		session.Save()

		if CheckPasswordHash(pwd, password) == true {
			c.JSON(200, gin.H{"status": "berhasil", "token": token})
		}
	})

	r.MaxMultipartMemory = 8 << 20
	r.Static("/", "./static")
	r.POST("/photos", func (c *gin.Context) {
		var user User
		var ath Auth

		token := c.PostForm("token")
		title := c.PostForm("title")
		caption := c.PostForm("caption")
		db.First(&ath, "token = ?", token)

		db.First(&user, ath.USER_ID)

		file, err := c.FormFile("file")
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
			return
		}

		filename := filepath.Base(file.Filename)
		if err := c.SaveUploadedFile(file, filename); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
			return
		}

		pt := Photo{TITLE: title, CAPTION: caption, PHOTO_URL: filename, USER_ID: user.ID}
		db.Create(&pt)

		c.String(http.StatusOK, fmt.Sprintf("File %s uploaded successfully", file.Filename))
	})

	r.DELETE("/users/:userId", func (c *gin.Context) {
		var user User
		var auth Auth
		session := sessions.Default(c)
		user_id := c.Param("userId")

		token := session.Get("token")
		if token == nil {
			c.JSON(401, gin.H{"status": "Unauthorized 1"})
			return
		}

		db.First(&auth, "token = ?", token)
		if auth == (Auth{}) {
			c.JSON(401, gin.H{"status": "User unknown"})
			return
		}

		db.First(&auth, "token = ?", token)
		if auth == (Auth{}) {
			c.JSON(401, gin.H{"status": "User unknown"})
			return
		}

		db.First(&user, user_id)
		if user == (User{}) {
			c.JSON(401, gin.H{"status": "User unknown"})
			return
		}

		if user.ID != auth.USER_ID {
			c.JSON(401, gin.H{"status": "Unauthorized 1"})
			return
		}

		db.Delete(&User{}, user_id)
		c.JSON(200, gin.H{"status": "Deleted"})
	})

	r.DELETE("/:imageId", func (c *gin.Context) {
		var auth Auth
		var photo Photo

		session := sessions.Default(c)
		token := session.Get("token")
		if token == nil {
			c.JSON(401, gin.H{"status": "Unauthorized 1"})
			return
		}

		db.First(&auth, "token = ?", token)
		if auth == (Auth{}) {
			c.JSON(401, gin.H{"status": "User unknown"})
			return
		}

		image_id := c.Param("imageId")
		db.First(&photo, image_id)

		if photo.USER_ID != auth.USER_ID {
			c.JSON(401, gin.H{"status": "Unauthorized 2"})
			return
		}
		db.Delete(&Photo{}, image_id)
		c.JSON(200, gin.H{"status": "Deleted"})
	})
	r.Run() // listen and serve on 0.0.0.0:8080
}
