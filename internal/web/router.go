package web

import (
	"database/sql"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"dsdns/internal/config"
)

//go:embed static/*
var StaticFiles embed.FS

// StatsGetter 接口用于获取统计信息
type StatsGetter interface {
	GetStats() (dnsQueries uint64, fakeVisits uint64)
}

type Handler struct {
	DB          *sql.DB
	Config      *config.Config
	statsGetter StatsGetter
}

func NewHandler(db *sql.DB, cfg *config.Config) *Handler {
	return &Handler{DB: db, Config: cfg}
}

// SetStatsGetter 设置统计提供者
func (h *Handler) SetStatsGetter(getter StatsGetter) {
	h.statsGetter = getter
}

// Router 返回 HTTP 路由
func (h *Handler) Router() http.Handler {
	SetJWTSecret(h.Config.JWT.Secret)

	mux := http.NewServeMux()

	// 静态文件
	staticFS, err := fs.Sub(StaticFiles, "static")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(staticFS))
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))

	// 单页入口（登录页）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		// 直接返回登录页
		http.ServeFileFS(w, r, staticFS, "login.html")
	})

	// API 路由
	api := http.NewServeMux()
	api.HandleFunc("/api/status", h.handleStatus)
	api.HandleFunc("/api/stats", h.handleStats) // 新增统计接口
	api.HandleFunc("/api/register", h.handleRegister)
	api.HandleFunc("/api/login", h.handleLogin)
	api.HandleFunc("/api/users", h.jwtAuth(h.handleUsers))
	api.HandleFunc("/api/domains", h.jwtAuth(h.handleDomains))
	api.HandleFunc("/api/domains/", h.jwtAuth(h.handleDomainByID))

	mux.Handle("/api/", api)

	return mux
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

// handleStats 返回统计信息
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if h.statsGetter == nil {
		http.Error(w, "stats not available", http.StatusServiceUnavailable)
		return
	}
	dnsQueries, fakeVisits := h.statsGetter.GetStats()
	json.NewEncoder(w).Encode(map[string]uint64{
		"dns_queries": dnsQueries,
		"fake_visits": fakeVisits,
	})
}
