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
	ID           int    `json:"id"`
	Title        string `json:"title"`
	Vendedor     string `json:"vendedor"`
	Calificacion int    `json:"calificacion"`
	ImageURL     string `json:"image_url"`
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
	r.Post("/logout", Logout)
	r.Get("/articles", GetArticles)
	r.Get("/fav_articles", GetFavoriteArticles)
	r.Post("/add_fav", AddFavoriteArticle)
	r.Post("/add_article", AddArticle)
	r.Delete("/favorite_articles/{articleID}", RemoveFavoriteArticle)
	r.Delete("/articles/{articleID}", RemoveArticle)

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
	rows, err := db.Query("SELECT id, title, vendedor, calificacion, image_url FROM articles")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var articles []Article
	for rows.Next() {
		var article Article
		err := rows.Scan(&article.ID, &article.Title, &article.Vendedor, &article.Calificacion, &article.ImageURL)
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

	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", claims.Username).Scan(&userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var favoriteArticleIDs []int
	rows, err := db.Query("SELECT article_id FROM favorite_articles WHERE user_id = ?", userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var articleID int
		err := rows.Scan(&articleID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		favoriteArticleIDs = append(favoriteArticleIDs, articleID)
	}

	// Check if there are any favorite articles before proceeding
	if len(favoriteArticleIDs) == 0 {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]Article{}) // Return an empty slice
		return
	}

	// Obtener los detalles de los artículos favoritos
	var favoriteArticles []Article
	for _, articleID := range favoriteArticleIDs {
		var article Article
		err := db.QueryRow("SELECT id, title, vendedor, calificacion , image_url FROM articles WHERE id = ?", articleID).Scan(&article.ID, &article.Title, &article.Vendedor, &article.Calificacion)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		favoriteArticles = append(favoriteArticles, article)
	}

	// Devolver los artículos favoritos como respuesta
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

	// Verificar y decodificar el token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Token inválido", http.StatusUnauthorized)
		return
	}

	// Consultar la base de datos para obtener el ID del usuario
	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", claims.Username).Scan(&userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var favArticle FavoriteArticle
	err = json.NewDecoder(r.Body).Decode(&favArticle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO favorite_articles (user_id, article_id) VALUES (?, ?)", userID, favArticle.ArticleID)
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

func Logout(w http.ResponseWriter, r *http.Request) {
	// El token se invalidará estableciendo una fecha de expiración en el pasado
	expirationTime := time.Now().Add(-1 * time.Minute) // Establecer una fecha en el pasado
	claims := &Claims{
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

	// Escribir el nuevo token inválido en la respuesta para invalidar el token actual en el cliente
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func AddArticle(w http.ResponseWriter, r *http.Request) {
	var article Article
	err := json.NewDecoder(r.Body).Decode(&article)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar si el campo ImageURL está presente en la solicitud
	if article.ImageURL == "" {
		http.Error(w, "El campo image_url es obligatorio", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO articles (title, vendedor, calificacion, image_url) VALUES (?, ?, ?, ?)", article.Title, article.Vendedor, article.Calificacion, article.ImageURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Artículo agregado exitosamente"))
}

func RemoveArticle(w http.ResponseWriter, r *http.Request) {
	// Obtener el ID del artículo de los parámetros de la URL
	articleID := chi.URLParam(r, "articleID")
	if articleID == "" {
		http.Error(w, "ID de artículo no proporcionado", http.StatusBadRequest)
		return
	}

	// Ejecutar la consulta para eliminar el artículo
	_, err := db.Exec("DELETE FROM articles WHERE id = ?", articleID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Si se eliminó correctamente, devolver una respuesta exitosa
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Artículo eliminado exitosamente"))
}

// Estructura para JWT
type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}
