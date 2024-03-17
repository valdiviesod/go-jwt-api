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

// User representa la estructura de datos para los usuarios
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Article representa la estructura de datos para los artículos
type Article struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// FavoriteArticle representa la estructura de datos para los artículos favoritos de los usuarios
type FavoriteArticle struct {
	UserID    int `json:"user_id"`
	ArticleID int `json:"article_id"`
}

var db *sql.DB
var jwtKey []byte

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error cargando el archivo .env")
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
	r.Get("/articles", GetArticles)
	r.Get("/favorite_articles", GetFavoriteArticles)
	r.Post("/favorite_articles", AddFavoriteArticle)
	r.Delete("/favorite_articles/{articleID}", RemoveFavoriteArticle)

	port := ":8080"
	log.Printf("Servidor iniciado en el puerto %s\n", port)
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
		UserID:   user.ID, // Suponiendo que tengas un campo ID en tu estructura User
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

	// Escribir el token en la respuesta
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func GetArticles(w http.ResponseWriter, r *http.Request) {
	// Consultar la base de datos para obtener la lista de artículos
	rows, err := db.Query("SELECT id, title, description FROM articles")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var article Article
		err := rows.Scan(&article.ID, &article.Title, &article.Description)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		articles = append(articles, article)
	}

	jsonData, err := json.Marshal(articles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func GetFavoriteArticles(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Token no proporcionado", http.StatusUnauthorized)
		return
	}

	// Verificar y decodificar el token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT article_id FROM favorite_articles WHERE user_id = ?", claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var favoriteArticleIDs []int
	for rows.Next() {
		var articleID int
		err := rows.Scan(&articleID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		favoriteArticleIDs = append(favoriteArticleIDs, articleID)
	}

	var favoriteArticles []Article
	for _, articleID := range favoriteArticleIDs {
		var article Article
		err := db.QueryRow("SELECT id, title, description FROM articles WHERE id = ?", articleID).Scan(&article.ID, &article.Title, &article.Description)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		favoriteArticles = append(favoriteArticles, article)
	}

	jsonData, err := json.Marshal(favoriteArticles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func AddFavoriteArticle(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Token no proporcionado", http.StatusUnauthorized)
		return
	}

	var favArticle FavoriteArticle
	err := json.NewDecoder(r.Body).Decode(&favArticle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar y decodificar el token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec("INSERT INTO favorite_articles (user_id, article_id) VALUES (?, ?)", claims.UserID, favArticle.ArticleID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Artículo agregado a favoritos"))
}

func RemoveFavoriteArticle(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Token no proporcionado", http.StatusUnauthorized)
		return
	}

	articleID := chi.URLParam(r, "articleID")
	if articleID == "" {
		http.Error(w, "ID de artículo no proporcionado", http.StatusBadRequest)
		return
	}

	// Verificar y decodificar el token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}

	_, err = db.Exec("DELETE FROM favorite_articles WHERE user_id = ? AND article_id = ?", claims.UserID, articleID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Artículo eliminado de favoritos"))
}

// Estructura para JWT
type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}
