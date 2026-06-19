package dns

import (
	"context"
	"database/sql"
	"net"
	"sync"
	"time"

	"dsdns/internal/logger"
	"dsdns/internal/models"
)

type ANAMEManager struct {
	db     *sql.DB
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewANAMEManager(db *sql.DB) *ANAMEManager {
	return &ANAMEManager{db: db, stopCh: make(chan struct{})}
}

func (m *ANAMEManager) Start(ctx context.Context) {
	m.wg.Add(1)
	go m.loop(ctx)
}

func (m *ANAMEManager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
}

func (m *ANAMEManager) loop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.syncAll()
		}
	}
}

func (m *ANAMEManager) syncAll() {
	rows, err := m.db.Query(`
		SELECT r.id, r.domain_id, r.rule_type, r.continent, r.isp, r.province, r.value, r.ttl, d.domain
		FROM records r JOIN domains d ON d.id = r.domain_id
		WHERE r.type = 'ANAME'
	`)
	if err != nil {
		logger.Error("ANAME sync query error", "error", err)
		return
	}
	defer rows.Close()

	type anameRec struct {
		rec    *models.Record
		domain string
	}
	var anames []anameRec
	for rows.Next() {
		var rec models.Record
		var domain string
		err := rows.Scan(&rec.ID, &rec.DomainID, &rec.RuleType, &rec.Continent, &rec.ISP, &rec.Province, &rec.Value, &rec.TTL, &domain)
		if err != nil {
			logger.Error("scan aname error", "error", err)
			continue
		}
		anames = append(anames, anameRec{rec: &rec, domain: domain})
	}

	for _, item := range anames {
		m.syncOne(item.rec, item.domain)
	}
}

func (m *ANAMEManager) syncOne(rec *models.Record, domain string) {
	target := rec.Value
	aRecords, aaaaRecords := resolveTarget(target)

	tx, err := m.db.Begin()
	if err != nil {
		logger.Error("begin tx error", "error", err)
		return
	}
	defer tx.Rollback()

	// 删除旧的自动记录（同一规则下的 generated=1）
	_, err = tx.Exec(`
		DELETE FROM records
		WHERE domain_id = ? AND rule_type = ? AND continent = ? AND isp = ? AND province = ? AND generated = 1
	`, rec.DomainID, rec.RuleType, rec.Continent, rec.ISP, rec.Province)
	if err != nil {
		logger.Error("delete old generated error", "error", err)
		return
	}

	// 插入新的 A 记录
	for _, ip := range aRecords {
		_, err = tx.Exec(`
			INSERT INTO records (domain_id, rule_type, continent, isp, province, type, value, ttl, generated)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
		`, rec.DomainID, rec.RuleType, rec.Continent, rec.ISP, rec.Province, models.TypeA, ip, rec.TTL)
		if err != nil {
			logger.Error("insert A generated error", "error", err)
			return
		}
	}
	// 插入新的 AAAA 记录
	for _, ip := range aaaaRecords {
		_, err = tx.Exec(`
			INSERT INTO records (domain_id, rule_type, continent, isp, province, type, value, ttl, generated)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
		`, rec.DomainID, rec.RuleType, rec.Continent, rec.ISP, rec.Province, models.TypeAAAA, ip, rec.TTL)
		if err != nil {
			logger.Error("insert AAAA generated error", "error", err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		logger.Error("commit tx error", "error", err)
	}
}

func resolveTarget(target string) (a []string, aaaa []string) {
	ips, err := net.LookupIP(target)
	if err != nil {
		logger.Warn("resolve target failed", "target", target, "error", err)
		return
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			a = append(a, ip.String())
		} else if ip.To16() != nil {
			aaaa = append(aaaa, ip.String())
		}
	}
	return
}
