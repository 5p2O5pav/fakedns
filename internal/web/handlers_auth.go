package web

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
)

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 仅当无管理员时允许注册
	hasAdmin, _ := h.hasAdmin()
	if hasAdmin {
		http.Error(w, "admin already exists", http.StatusForbidden)
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(input.Username)
	password := strings.TrimSpace(input.Password)
	if username == "" || password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	hash, err := HashPassword(password)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = h.DB.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)", username, hash)
	if err != nil {
		http.Error(w, "username already taken", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "admin registered"})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var user struct {
		ID           int64
		PasswordHash string
		IsAdmin      bool
	}
	err := h.DB.QueryRow("SELECT id, password_hash, is_admin FROM users WHERE username=?", input.Username).
		Scan(&user.ID, &user.PasswordHash, &user.IsAdmin)
	if err == sql.ErrNoRows || !CheckPassword(user.PasswordHash, input.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	token, err := GenerateToken(user.ID, user.IsAdmin, h.Config.JWT.ExpireHours)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}
