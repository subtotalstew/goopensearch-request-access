package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/opensearch-project/opensearch-go/v2"
)

var db *sql.DB
var opensearchClient *opensearch.Client

type Request struct {
	ID          int
	Username    string
	Index       string
	IncidentNum string
	Approved    bool
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./requests.db")
	if err != nil {
		log.Fatal(err)
	}
	createTable()
}

func createTable() {
	createTableSQL := `CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        index_name TEXT NOT NULL,
        incident_num TEXT NOT NULL,
        approved BOOLEAN DEFAULT FALSE
    );`
	_, err := db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}
}

func initOpenSearchClient() {
	var err error

	// Загрузка сертификата и ключа
	cert, err := tls.LoadX509KeyPair("cert.pem", "cert.key")
	if err != nil {
		log.Fatalf("Error loading certificate and key: %s", err)
	}

	// Создание TLS конфигурации
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Используйте это только для тестирования
	}

	// Создание HTTP транспорта с TLS
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Инициализация OpenSearch клиента
	opensearchClient, err = opensearch.NewClient(opensearch.Config{
		Addresses: []string{
			"https://localhost:9200", // Замените на ваш адрес OpenSearch
		},
		Username:  "admin", // Замените на ваше имя пользователя
		Password:  "admin", // Замените на ваш пароль
		Transport: transport,
	})
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	initDB()
	initOpenSearchClient()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	r.POST("/submit", func(c *gin.Context) {
		username := c.PostForm("username")
		index := c.PostForm("index")
		incidentNum := c.PostForm("incidentNum")
		_, err := db.Exec("INSERT INTO requests (username, index_name, incident_num) VALUES (?, ?, ?)", username, index, incidentNum)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Redirect(http.StatusFound, "/")
	})

	r.GET("/admin", authMiddleware, func(c *gin.Context) {
		rows, err := db.Query("SELECT id, username, index_name, incident_num, approved FROM requests")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()

		var requests []Request
		for rows.Next() {
			var r Request
			err := rows.Scan(&r.ID, &r.Username, &r.Index, &r.IncidentNum, &r.Approved)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			requests = append(requests, r)
		}

		c.HTML(http.StatusOK, "admin.html", gin.H{"Requests": requests, "Authenticated": true})
	})

	r.POST("/admin/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		if username == "admin" && password == "admin" {
			c.SetCookie("authenticated", "true", 3600, "/", "localhost", false, true)
			c.Redirect(http.StatusFound, "/admin")
		} else {
			c.HTML(http.StatusOK, "admin.html", gin.H{"Authenticated": false})
		}
	})

	r.POST("/logout", func(c *gin.Context) {
		c.SetCookie("authenticated", "", -1, "/", "localhost", false, true)
		c.Redirect(http.StatusFound, "/admin")
	})

	r.POST("/approve", func(c *gin.Context) {
		id := c.PostForm("id")
		_, err := db.Exec("UPDATE requests SET approved = TRUE WHERE id = ?", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var request Request
		err = db.QueryRow("SELECT username, index_name, incident_num FROM requests WHERE id = ?", id).Scan(&request.Username, &request.Index, &request.IncidentNum)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		updateDLS(request.Index, request.Username)
		go revertDLS(request.Index, request.Username, 2*time.Hour)

		c.Redirect(http.StatusFound, "/admin")
	})

	r.POST("/revoke", func(c *gin.Context) {
		id := c.PostForm("id")
		_, err := db.Exec("UPDATE requests SET approved = FALSE WHERE id = ?", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var request Request
		err = db.QueryRow("SELECT username, index_name, incident_num FROM requests WHERE id = ?", id).Scan(&request.Username, &request.Index, &request.IncidentNum)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		updateDLS(request.Index, "")

		c.Redirect(http.StatusFound, "/admin")
	})

	r.Run(":8080")
}

func authMiddleware(c *gin.Context) {
	cookie, err := c.Cookie("authenticated")
	if err != nil || cookie != "true" {
		c.HTML(http.StatusOK, "admin.html", gin.H{"Authenticated": false})
		c.Abort()
		return
	}
	c.Next()
}

func updateDLS(index, username string) {
	reqBody := map[string]interface{}{
		"cluster_permissions": []interface{}{},
		"index_permissions": []interface{}{
			map[string]interface{}{
				"index_patterns":  []string{index},
				"dls":             fmt.Sprintf("{\"term\": {\"user\": \"%s\"}}", username),
				"fls":             []interface{}{},
				"masked_fields":   []interface{}{},
				"allowed_actions": []string{"read"},
			},
		},
		"tenant_permissions": []interface{}{},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		log.Fatalf("Error marshalling request body: %s", err)
	}

	req, err := http.NewRequest("PUT", "https://localhost:9200/_plugins/_security/api/roles/my_role", bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("Error creating request: %s", err)
	}
	req.Header.Set("Content-Type", "application/json")

	log.Printf("Sending request to OpenSearch: %s", req.URL.String())
	log.Printf("Request body: %s", body)

	resp, err := opensearchClient.Perform(req)
	if err != nil {
		log.Fatalf("Error performing request: %s", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %s", err)
	}

	log.Printf("Response status: %s", resp.Status)
	log.Printf("Response body: %s", respBody)

	fmt.Println("Role updated successfully")
}

func revertDLS(index, username string, duration time.Duration) {
	time.Sleep(duration)
	updateDLS(index, username)
}
