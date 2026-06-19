package dns

import (
	"database/sql"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"dsdns/internal/geo"
	"dsdns/internal/logger"
	"dsdns/internal/models"
)

// DBQuerier 定义查询接口（由 db.Querier 实现）
type DBQuerier interface {
	LookupRecords(domain string) ([]*models.Record, error)
}

// GeoResolver 定义地理信息查询接口
type GeoResolver interface {
	GetGeoInfo(ip net.IP) (*geo.GeoInfo, int)
}

// Stats 统计信息
type Stats struct {
	DoHQueries   uint64
	FakeVisits   uint64
}

// DoHServer 实现 http.Handler，处理 DoH 和伪装
type DoHServer struct {
	db         *sql.DB            // 用于 ANAME 管理
	querier    DBQuerier
	geo        GeoResolver
	domain     string             // FQDN，如 "example.com."
	stats      *Stats
	anameMgr   *ANAMEManager
}

// NewDoHServer 创建 DoH 服务器
func NewDoHServer(querier DBQuerier, geo GeoResolver, domain string, db *sql.DB) *DoHServer {
	s := &DoHServer{
		db:      db,
		querier: querier,
		geo:     geo,
		domain:  dns.Fqdn(domain),
		stats:   &Stats{},
	}
	s.anameMgr = NewANAMEManager(db)
	return s
}

// StartANAMEManager 启动 ANAME 后台同步（在 main 中调用）
func (s *DoHServer) StartANAMEManager(ctx context.Context) {
	s.anameMgr.Start(ctx)
}

// StopANAMEManager 停止
func (s *DoHServer) StopANAMEManager() {
	s.anameMgr.Stop()
}

// GetStats 返回统计信息
func (s *DoHServer) GetStats() (dnsQueries uint64, fakeVisits uint64) {
	return atomic.LoadUint64(&s.stats.DoHQueries), atomic.LoadUint64(&s.stats.FakeVisits)
}

// ServeHTTP 处理所有 HTTP 请求
func (s *DoHServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 统计伪装访问（除 DoH 查询外）
	if r.URL.Path != "/dns-query" || r.Method != http.MethodPost {
		atomic.AddUint64(&s.stats.FakeVisits, 1)
	}

	switch r.URL.Path {
	case "/":
		s.serveWelcome(w, r)
		return
	case "/dns-query":
		if r.Method == http.MethodPost {
			s.serveDoH(w, r)
			return
		}
		// 非 POST 视为伪装请求，返回 404
		fallthrough
	default:
		http.NotFound(w, r)
	}
}

// serveWelcome 返回 Nginx 默认欢迎页
func (s *DoHServer) serveWelcome(w http.ResponseWriter, r *http.Request) {
	const welcomeHTML = `<!DOCTYPE html>
<html>
<head><title>Welcome to nginx!</title></head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(welcomeHTML))
}

// serveDoH 处理 DoH POST 请求
func (s *DoHServer) serveDoH(w http.ResponseWriter, r *http.Request) {
	// 检查 Content-Type
	if r.Header.Get("Content-Type") != "application/dns-message" {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		http.Error(w, "bad dns message", http.StatusBadRequest)
		return
	}

	if len(msg.Question) == 0 {
		http.Error(w, "no question", http.StatusBadRequest)
		return
	}
	q := msg.Question[0]
	qname := strings.ToLower(q.Name)

	// 仅允许查询配置的域名（含子域名）
	if !strings.HasSuffix(qname, s.domain) && qname != s.domain {
		http.NotFound(w, r)
		return
	}

	// 获取客户端 IP（优先 X-Forwarded-For）
	clientIP := s.extractClientIP(r)
	var geoInfo *geo.GeoInfo
	if clientIP != nil {
		geoInfo, _ = s.geo.GetGeoInfo(clientIP)
	} else {
		geoInfo = &geo.GeoInfo{}
	}

	// 查询记录（包括 generated=1 的 ANAME 生成记录）
	records, err := s.querier.LookupRecords(qname)
	if err != nil || len(records) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(msg)
		reply.SetRcode(msg, dns.RcodeNameError)
		s.writeDNSResponse(w, reply)
		return
	}

	// 匹配最佳记录（支持多记录返回）
	matched := s.matchRecords(records, geoInfo, q.Qtype)
	if len(matched) == 0 {
		reply := new(dns.Msg)
		reply.SetReply(msg)
		reply.SetRcode(msg, dns.RcodeSuccess)
		s.writeDNSResponse(w, reply)
		return
	}

	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.Authoritative = true
	for _, rec := range matched {
		rr := s.buildRR(qname, q.Qtype, rec)
		if rr != nil {
			reply.Answer = append(reply.Answer, rr)
		}
	}
	s.writeDNSResponse(w, reply)

	// 增加查询统计
	atomic.AddUint64(&s.stats.DoHQueries, 1)
}

// matchRecords 返回匹配的所有记录（按优先级排序）
func (s *DoHServer) matchRecords(records []*models.Record, geo *geo.GeoInfo, qtype uint16) []*models.Record {
	// 过滤掉 ANAME 类型（ANAME 不直接响应）
	var filtered []*models.Record
	for _, rec := range records {
		if rec.Type == models.TypeANAME {
			continue
		}
		filtered = append(filtered, rec)
	}
	// 按规则评分
	type scored struct {
		rec   *models.Record
		score int
	}
	var scoredList []scored
	for _, rec := range filtered {
		score := matchScore(rec, geo)
		if score > 0 {
			// 手动记录优先级更高
			if rec.Generated == 0 {
				score += 1000
			}
			scoredList = append(scoredList, scored{rec, score})
		}
	}
	if len(scoredList) == 0 {
		return nil
	}
	// 按分数降序排序（简单冒泡）
	for i := 0; i < len(scoredList); i++ {
		for j := i + 1; j < len(scoredList); j++ {
			if scoredList[j].score > scoredList[i].score {
				scoredList[i], scoredList[j] = scoredList[j], scoredList[i]
			}
		}
	}
	// 选取最高分
	maxScore := scoredList[0].score
	var result []*models.Record
	for _, s := range scoredList {
		if s.score == maxScore {
			result = append(result, s.rec)
		}
	}
	// 再按类型过滤（只保留 qtype 匹配的）
	var final []*models.Record
	for _, rec := range result {
		switch qtype {
		case dns.TypeA:
			if rec.Type == models.TypeA {
				final = append(final, rec)
			}
		case dns.TypeAAAA:
			if rec.Type == models.TypeAAAA {
				final = append(final, rec)
			}
		case dns.TypeCNAME:
			if rec.Type == models.TypeCNAME {
				final = append(final, rec)
			}
		default:
			// 其他类型暂不支持
		}
	}
	return final
}

// matchScore 与原有逻辑一致，但此处我们复制原 server.go 中的 matchScore 函数
// 为了简洁，直接引用原函数（但原函数在 server.go 中已删除，此处复制）
func matchScore(rec *models.Record, geo *geo.GeoInfo) int {
	switch rec.RuleType {
	case "default":
		return 1
	case "continent":
		if geo.Continent == rec.Continent {
			return 10
		}
		return 0
	case "china_other":
		if geo.IsChina && !geo.IsMainland {
			return 20
		}
		if geo.IsChina && geo.IsMainland && (geo.ISP == "" || geo.Province == "") {
			return 20
		}
		return 0
	case "china":
		if !geo.IsMainland {
			return 0
		}
		if rec.ISP != "" && rec.ISP != geo.ISP {
			return 0
		}
		if rec.Province != "" {
			keyword := strings.ToLower(rec.Province)
			if !strings.Contains(strings.ToLower(geo.Province), keyword) &&
				!strings.Contains(strings.ToLower(geo.City), keyword) {
				return 0
			}
		}
		if rec.ISP != "" && rec.Province != "" {
			return 100
		} else if rec.ISP != "" {
			return 90
		} else if rec.Province != "" {
			return 80
		} else {
			return 70
		}
	}
	return 0
}

// buildRR 构建单个 RR
func (s *DoHServer) buildRR(domain string, qtype uint16, rec *models.Record) dns.RR {
	header := dns.RR_Header{
		Name:   domain,
		Rrtype: qtype,
		Class:  dns.ClassINET,
		Ttl:    uint32(rec.TTL),
	}
	switch rec.Type {
	case models.TypeA:
		if qtype == dns.TypeA {
			ip := net.ParseIP(rec.Value)
			if ip != nil {
				return &dns.A{Hdr: header, A: ip}
			}
		}
	case models.TypeAAAA:
		if qtype == dns.TypeAAAA {
			ip := net.ParseIP(rec.Value)
			if ip != nil {
				return &dns.AAAA{Hdr: header, AAAA: ip}
			}
		}
	case models.TypeCNAME:
		if qtype == dns.TypeCNAME || qtype == dns.TypeA || qtype == dns.TypeAAAA {
			return &dns.CNAME{Hdr: header, Target: dns.Fqdn(rec.Value)}
		}
	}
	return nil
}

// writeDNSResponse 写入二进制 DNS 响应
func (s *DoHServer) writeDNSResponse(w http.ResponseWriter, reply *dns.Msg) {
	data, err := reply.Pack()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// extractClientIP 从请求中提取客户端 IP（优先 X-Forwarded-For）
func (s *DoHServer) extractClientIP(r *http.Request) net.IP {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := net.ParseIP(strings.TrimSpace(ips[0]))
			if ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
