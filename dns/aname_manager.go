package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"dsdns/internal/logger"
	"dsdns/internal/models"
)

type DBQuerier interface {
	LookupRecords(domain string) ([]*models.Record, error)
	// 需要额外方法用于更新记录，这里我们直接在 DoHServer 中使用 db 执行 SQL
	// 因此我们需要暴露 db 的 Exec 方法，或者通过接口扩展
	// 为简单起见，我们在 DoHServer 中持有 *sql.DB，但这里我们传入 DB 引用
}

// 实际实现中，我们会在 main 中初始化一个 *sql.DB 并传给 DoHServer
// 此处简化：在 DoHServer 中包含 db *sql.DB，但为了不破坏接口，我们定义一个扩展接口
type DBExecutor interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

// DoHServer 中增加 dbExecutor 字段
// 修改 DoHServer 结构：加入 db DBExecutor

type ANAMEManager struct {
	db     DBExecutor
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewANAMEManager(db DBExecutor) *ANAMEManager {
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
	ticker := time.NewTicker(60 * time.Second) // 每60秒检查一次
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
	// 查询所有 ANAME 记录
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
		rec      *models.Record
		domain   string // 所属域名
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
	// 解析目标域名，获取 A 和 AAAA 记录
	aRecords, aaaaRecords := resolveTarget(target)

	// 更新数据库：删除旧的 generated=1 记录，插入新记录（或更新）
	// 先删除该 domain_id 下、rule_type、continent、isp、province 相同的 generated=1 的记录
	// 然后插入新的
	// 使用事务
	tx, err := m.db.(*sql.DB).Begin() // 暂时类型断言，实际应使用接口
	if err != nil {
		logger.Error("begin tx error", "error", err)
		return
	}
	defer tx.Rollback()

	// 删除旧自动记录
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
	// 使用 net.LookupIP
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
