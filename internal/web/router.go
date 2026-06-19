package web

import (
	"database/sql"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strings"

	"dsdns/internal/config"
)

type Handler struct {
	DB     *sql.DB
	Config *config.Config
}

func NewHandler(db *sql.DB, cfg *config.Config) *Handler {
	return &Handler{DB: db, Config: cfg}
}

func (h *Handler) Start() error {
	SetJWTSecret(h.Config.JWT.Secret)

	mux := http.NewServeMux()

	// 静态文件
	staticFS, err := fs.Sub(StaticFiles, "static")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// 单页入口
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		hasAdmin, _ := h.hasAdmin()
		if hasAdmin {
			http.ServeFileFS(w, r, staticFS, "login.html")
		} else {
			http.ServeFileFS(w, r, staticFS, "login.html")
		}
	})

	// API 路由
	api := http.NewServeMux()
	api.HandleFunc("/api/status", h.handleStatus)
	api.HandleFunc("/api/register", h.handleRegister)
	api.HandleFunc("/api/login", h.handleLogin)
	api.HandleFunc("/api/users", h.jwtAuth(h.handleUsers))
	api.HandleFunc("/api/domains", h.jwtAuth(h.handleDomains))      // GET, POST
	api.HandleFunc("/api/domains/", h.jwtAuth(h.handleDomainByID))  // GET, PUT, PATCH, DELETE

	mux.Handle("/api/", api)

	addr := h.Config.Web.Listen
	log.Printf("Web management listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (h *Handler) hasAdmin() (bool, error) {
	var count int
	err := h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin=1").Scan(&count)
	return count > 0, err
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	hasAdmin, _ := h.hasAdmin()
	json.NewEncoder(w).Encode(map[string]bool{"has_admin": hasAdmin})
}
