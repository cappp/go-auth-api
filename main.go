package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Login struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type User struct {
	Name     string `json:"name" binding:"required"`
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func main() {
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	router := gin.Default()

	router.GET("/", func(ctx *gin.Context) {
		if _, err = ctx.Cookie("logado"); err != nil {
			ctx.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "mensagem": "E ai piva. Você não tá logado."})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "mensagem": "E aí piva. Você tá logado."})
	})

	router.GET("/logout", func(ctx *gin.Context) {
		if _, err = ctx.Cookie("logado"); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "mensagem": "Você não tá logado."})
			return
		}
		ctx.SetCookie("logado", "", -1, "/", "localhost", false, false)
		ctx.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "mensagem": "Você foi deslogado com sucesso."})
	})

	router.POST("/login", func(ctx *gin.Context) {
		if _, err := ctx.Cookie("logado"); err == nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "mensagem": "Você já está logado!"})
			return
		}

		var login Login

		if err := ctx.ShouldBindJSON(&login); err != nil {
			log.Println(err)
			ctx.JSON(http.StatusBadRequest, gin.H{"mensagem": "Tá errado isso aí viu."})
			return
		}

		dbUserRow := db.QueryRow("select name, username, password from users where username like ?", login.Username)

		var dbUser User

		switch err := dbUserRow.Scan(&dbUser.Name, &dbUser.Username, &dbUser.Password); err {
		case sql.ErrNoRows:
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "mensagem": "Esse seu username pau no xibiu não existe não."})
			return
		case nil:
			break
		default:
			log.Println(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "mensagem": "Ocorreu um erro ao logar na sua conta."})
			return
		}

		isTheSamePassword := CheckPasswordHash(login.Password, dbUser.Password)
		if !isTheSamePassword {
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": http.StatusUnauthorized, "mensagem": "A senha tá errada viu mano."})
			return
		}

		ctx.SetCookie("logado", "", 3600, "/", "localhost", false, false)
		ctx.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "mensagem": "Você foi logado com sucesso!"})
	})

	router.POST("/signup", func(ctx *gin.Context) {
		var user User

		if err := ctx.ShouldBindJSON(&user); err != nil {
			log.Println(err)
			ctx.JSON(http.StatusBadRequest, gin.H{"mensagem": "Tá errado isso aí viu."})
			return
		}

		dbUsernameRow := db.QueryRow("select username from users where username like ?", user.Username)

		var username string

		switch err := dbUsernameRow.Scan(&username); err {
		case sql.ErrNoRows:
			break
		case nil:
			ctx.JSON(http.StatusBadRequest, gin.H{"status": http.StatusBadRequest, "mensagem": "Já tem esse username aí rapaz!"})
			return
		default:
			log.Println(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "mensagem": "Ocorreu um erro ao criar sua conta."})
			return
		}

		hashedUserPassword, err := HashPassword(user.Password)
		if err != nil {
			log.Println(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "mensagem": "Ocorreu um erro ao criar sua conta."})
			return
		}

		_, err = db.Exec("insert into users(name, username, password) values(?, ?, ?)", user.Name, user.Username, hashedUserPassword)
		if err != nil {
			log.Println(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"status": http.StatusInternalServerError, "mensagem": "Ocorreu um erro ao criar sua conta."})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "mensagem": "Sua conta foi criada."})
	})

	router.Run(":3000")
}
