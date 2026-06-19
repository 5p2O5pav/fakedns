package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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

type DoHServer struct {
	db       DBQuerier
	geo      GeoResolver
	domain   string          // 管理的域名 (如 example.com)
	stats    *Stats          // 统计
	anameMgr *ANAMEManager   // ANAME 后台管理
}

type Stats struct {
	DoHQueries   uint64
	FakeVisits   uint64
}

func NewDoHServer(db DBQuerier, geo GeoResolver, domain string) *DoHServer {
	s := &DoHServer{
		db:     db,
		geo:    geo,
		domain: dns.Fqdn(domain), // 确保以点结尾
		stats:  &Stats{},
	}
	s.anameMgr = NewANAMEManager(db)
	return s
}

// ServeHTTP 实现 http.Handler，处理所有请求
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

// serveWelcome 返回 Nginx 默认欢迎页（可嵌入或读取文件）
func (s *DoHServer) serveWelcome(w http.ResponseWriter, r *http.Request) {
	// 这里直接返回内置的 Nginx 欢迎页 HTML
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

	// 解析 DNS 消息
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

	// 仅允许查询配置的域名（或子域名？可根据需要调整）
	if !strings.HasSuffix(qname, s.domain) && qname != s.domain {
		// 未配置的域名，返回 404（伪装）
		http.NotFound(w, r)
		return
	}

	// 获取客户端 IP
	clientIP := s.extractClientIP(r)
	var geoInfo *geo.GeoInfo
	if clientIP != nil {
		geoInfo, _ = s.geo.GetGeoInfo(clientIP)
	} else {
		geoInfo = &geo.GeoInfo{}
	}

	// 查询数据库中的记录（包括 generated=1 的 ANAME 生成记录）
	records, err := s.db.LookupRecords(qname)
	if err != nil || len(records) == 0 {
		// 没有记录，返回 NXDOMAIN
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

	// 构建响应
	reply := new(dns.Msg)
	reply.SetReply(msg)
	reply.Authoritative = true
	for _, rec := range matched {
		rr := s.buildRR(qname, q.Qtype, rec)
		if rr != nil {
			reply.Answer = append(reply.Answer, rr)
		}
	}
	// 如果查询类型是 A 或 AAAA，且返回了 CNAME，需要按标准处理？但这里简化，只返回匹配记录
	s.writeDNSResponse(w, reply)

	// 增加查询统计
	atomic.AddUint64(&s.stats.DoHQueries, 1)
}

// matchRecords 返回匹配的所有记录（按优先级排序）
func (s *DoHServer) matchRecords(records []*models.Record, geo *geo.GeoInfo, qtype uint16) []*models.Record {
	// 先过滤掉 ANAME 类型（ANAME 不直接响应）
	var filtered []*models.Record
	for _, rec := range records {
		if rec.Type == models.TypeANAME {
			continue // ANAME 由后台生成实际记录
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
	// 按分数降序排序
	// 简单冒泡（实际可 sort.Slice）
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
			// 标准做法是返回 CNAME，让客户端继续解析
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
	// 尝试 X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := net.ParseIP(strings.TrimSpace(ips[0]))
			if ip != nil {
				return ip
			}
		}
	}
	// 回退 RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
