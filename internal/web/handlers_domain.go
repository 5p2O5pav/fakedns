package web

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"dsdns/internal/models"
)

// handleDomains 列出用户的域名或创建新域名
func (h *Handler) handleDomains(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := h.DB.Query("SELECT id, user_id, domain, created_at FROM domains WHERE user_id=? ORDER BY id", claims.UserID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		domains := []models.Domain{}
		for rows.Next() {
			var d models.Domain
			if err := rows.Scan(&d.ID, &d.UserID, &d.Domain, &d.CreatedAt); err != nil {
				continue
			}
			domains = append(domains, d)
		}
		json.NewEncoder(w).Encode(domains)

	case http.MethodPost:
		var input struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		domain := dnsFqdn(input.Domain)
		if domain == "" {
			http.Error(w, "invalid domain", http.StatusBadRequest)
			return
		}
		var exists int
		h.DB.QueryRow("SELECT COUNT(*) FROM domains WHERE domain=?", domain).Scan(&exists)
		if exists > 0 {
			http.Error(w, "domain already exists", http.StatusConflict)
			return
		}
		res, err := h.DB.Exec("INSERT INTO domains (user_id, domain) VALUES (?, ?)", claims.UserID, domain)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		id, _ := res.LastInsertId()
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.Domain{ID: id, UserID: claims.UserID, Domain: domain})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDomainRecordsGet 获取域名下的所有记录
func (h *Handler) handleDomainRecordsGet(domainID int64, w http.ResponseWriter) {
	rows, err := h.DB.Query(`
		SELECT id, rule_type, continent, isp, province, type, value, ttl
		FROM records WHERE domain_id = ?
	`, domainID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	records := make([]models.Record, 0)
	for rows.Next() {
		var rec models.Record
		err := rows.Scan(&rec.ID, &rec.RuleType, &rec.Continent, &rec.ISP, &rec.Province, &rec.Type, &rec.Value, &rec.TTL)
		if err != nil {
			continue
		}
		records = append(records, rec)
	}
	json.NewEncoder(w).Encode(records)
}

// handleDomainRecordsPut 替换域名下的所有记录
func (h *Handler) handleDomainRecordsPut(domainID int64, w http.ResponseWriter, r *http.Request) {
	var records []models.Record
	if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	hasDefault := false
	for _, rec := range records {
		if rec.RuleType == "default" {
			hasDefault = true
			break
		}
	}
	if !hasDefault {
		http.Error(w, "default rule required", http.StatusBadRequest)
		return
	}
	allowedTTL := map[int]bool{60: true, 300: true, 600: true, 1200: true, 3600: true}
	for _, rec := range records {
		if rec.Type != models.TypeA && rec.Type != models.TypeAAAA && rec.Type != models.TypeCNAME {
			http.Error(w, "invalid record type", http.StatusBadRequest)
			return
		}
		if !allowedTTL[rec.TTL] {
			http.Error(w, "invalid ttl", http.StatusBadRequest)
			return
		}
		switch rec.RuleType {
		case "default":
		case "continent":
			if rec.Continent == "" {
				http.Error(w, "continent required", http.StatusBadRequest)
				return
			}
		case "china_other":
		case "china":
		default:
			http.Error(w, "invalid rule_type", http.StatusBadRequest)
			return
		}
	}
	tx, err := h.DB.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	_, err = tx.Exec("DELETE FROM records WHERE domain_id = ?", domainID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	for _, rec := range records {
		_, err = tx.Exec(`
			INSERT INTO records (domain_id, rule_type, continent, isp, province, type, value, ttl)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, domainID, rec.RuleType, rec.Continent, rec.ISP, rec.Province, rec.Type, rec.Value, rec.TTL)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	tx.Commit()
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "updated"})
}

// handleDomainRename 修改域名（迁移记录）
func (h *Handler) handleDomainRename(domainID int64, w http.ResponseWriter, r *http.Request) {
	var input struct {
		NewDomain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	newDomain := dnsFqdn(input.NewDomain)
	if newDomain == "" {
		http.Error(w, "invalid domain", http.StatusBadRequest)
		return
	}
	var exists int
	err := h.DB.QueryRow("SELECT COUNT(*) FROM domains WHERE domain = ? AND id != ?", newDomain, domainID).Scan(&exists)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		http.Error(w, "domain already exists", http.StatusConflict)
		return
	}
	_, err = h.DB.Exec("UPDATE domains SET domain = ? WHERE id = ?", newDomain, domainID)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "domain renamed"})
}

// handleDomainByID 根据 ID 处理域名（获取记录、更新记录、修改域名、删除域名）
func (h *Handler) handleDomainByID(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	if claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/domains/")
	domainID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	var userID int64
	err = h.DB.QueryRow("SELECT user_id FROM domains WHERE id = ?", domainID).Scan(&userID)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if userID != claims.UserID {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleDomainRecordsGet(domainID, w)
	case http.MethodPut:
		h.handleDomainRecordsPut(domainID, w, r)
	case http.MethodPatch:
		h.handleDomainRename(domainID, w, r)
	case http.MethodDelete:
		_, err = h.DB.Exec("DELETE FROM domains WHERE id = ?", domainID)
		if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// dnsFqdn 规范化域名为 FQDN 格式（以点结尾）
func dnsFqdn(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	return domain
}
