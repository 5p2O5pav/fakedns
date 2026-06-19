package db

import (
	"database/sql"
	"dsdns/internal/models"
)

type Querier struct {
	DB *sql.DB
}

// LookupRecords 返回域名下所有记录
func (q *Querier) LookupRecords(domain string) ([]*models.Record, error) {
	rows, err := q.DB.Query(`
		SELECT r.id, r.domain_id, r.rule_type, r.continent, r.isp, r.province, r.type, r.value, r.ttl
		FROM records r JOIN domains d ON d.id = r.domain_id
		WHERE d.domain = ?
	`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*models.Record
	for rows.Next() {
		rec := &models.Record{}
		err := rows.Scan(&rec.ID, &rec.DomainID, &rec.RuleType, &rec.Continent, &rec.ISP, &rec.Province, &rec.Type, &rec.Value, &rec.TTL)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}
