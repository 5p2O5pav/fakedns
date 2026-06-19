package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims == nil || !claims.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := h.DB.Query("SELECT id, username, is_admin, created_at FROM users ORDER BY id")
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		users := []struct {
			ID        int64  `json:"id"`
			Username  string `json:"username"`
			IsAdmin   bool   `json:"is_admin"`
			CreatedAt string `json:"created_at"`
		}{}
		for rows.Next() {
			var u struct {
				ID        int64  `json:"id"`
				Username  string `json:"username"`
				IsAdmin   bool   `json:"is_admin"`
				CreatedAt string `json:"created_at"`
			}
			if err := rows.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.CreatedAt); err != nil {
				continue
			}
			users = append(users, u)
		}
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
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
		_, err = h.DB.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)", username, hash)
		if err != nil {
			http.Error(w, "username already taken", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "user created"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
