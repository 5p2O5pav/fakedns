package web

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

const claimsKey contextKey = "claims"

func (h *Handler) jwtAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ParseToken(tokenStr)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

func getClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(claimsKey).(*Claims)
	return claims
}
