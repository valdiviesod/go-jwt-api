package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// User es una estructura de datos para almacenar valores de diferentes tipos y modelarlos
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var db *sql.DB
var jwtKey []byte

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	db, err = sql.Open("mysql", os.Getenv("DB_CONNECTION_STRING"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	jwtKey = []byte(os.Getenv("JWT_SECRET"))

	r := chi.NewRouter()
	r.Post("/register", Register)
	r.Post("/login", Login)
	r.Get("/test", TestToken)

	port := ":8080"
	log.Printf("Server started on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, r))

}

// Funciones HTTP y sus controladores
func Register(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar si el usuario ya existe en la base de datos
	var existingUser string
	err = db.QueryRow("SELECT username FROM users WHERE username = ?", user.Username).Scan(&existingUser)
	if err == nil {
		http.Error(w, "El nombre de usuario ya está en uso", http.StatusConflict)
		return
	} else if err != sql.ErrNoRows {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Si no hay errores y el usuario no existe, procedemos con el registro
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Usuario registrado exitosamente"))
}

func Login(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", user.Username).Scan(&storedPassword)
	if err != nil {
		http.Error(w, "Usuario o contraseña inválidos", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password))
	if err != nil {
		http.Error(w, "Usuario o contraseña inválidos", http.StatusUnauthorized)
		return
	}

	// Establecer la fecha de expiración del token en 7 días
	expirationTime := time.Now().Add(7 * 24 * time.Hour)

	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Guardar token en cookies para no perder la sesión
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Inicio de sesión exitoso"))
}

func TestToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Token no encontrado", http.StatusUnauthorized)
		return
	}

	// Leer la cookie
	tokenString := cookie.Value
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}

	if !token.Valid {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}

	// Verificar si el token ha expirado
	if time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
		http.Error(w, "Token expirado, por favor inicia sesión nuevamente", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Token válido"))
}

// Estructura para JWT
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}
