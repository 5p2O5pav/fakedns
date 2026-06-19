package dns

import (
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
	"dsdns/internal/logger"
	"dsdns/internal/models"
	"dsdns/internal/geo"
)

type Server struct {
	addr     string
	db       DBQuerier
	Resolver GeoResolver
}

type DBQuerier interface {
	LookupRecords(domain string) ([]*models.Record, error)
}

type GeoResolver interface {
	GetGeoInfo(ip net.IP) (*geo.GeoInfo, int)
}

func New(addr string, db DBQuerier, geo GeoResolver) *Server {
	return &Server{addr: addr, db: db, Resolver: geo}
}

func (s *Server) Start() error {
	dns.HandleFunc(".", s.handleDNS)
	udpServer := &dns.Server{Addr: s.addr, Net: "udp"}
	tcpServer := &dns.Server{Addr: s.addr, Net: "tcp"}

	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			logger.Error("UDP DNS server error", "error", err)
			os.Exit(1)
		}
	}()
	logger.Info("DNS server listening", "addr", s.addr)
	if err := tcpServer.ListenAndServe(); err != nil {
		logger.Error("TCP DNS server error", "error", err)
		return err
	}
	return nil
}

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	domain := strings.ToLower(q.Name)

	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA && q.Qtype != dns.TypeCNAME {
		logger.Debug("unsupported query type", "domain", domain, "qtype", q.Qtype)
		w.WriteMsg(m)
		return
	}

	logger.Debug("DNS request", "domain", domain)

	clientIP := s.extractClientIP(r, w.RemoteAddr())
	var geoInfo *geo.GeoInfo
	if clientIP != nil {
		geoInfo, _ = s.Resolver.GetGeoInfo(clientIP)
		logger.Debug("geo info", "ip", clientIP, "continent", geoInfo.Continent, "isMainland", geoInfo.IsMainland, "isp", geoInfo.ISP, "province", geoInfo.Province)
	} else {
		geoInfo = &geo.GeoInfo{}
		logger.Warn("no client IP, using empty geo")
	}

	records, err := s.db.LookupRecords(domain)
	if err != nil || len(records) == 0 {
		logger.Warn("no records for domain", "domain", domain)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return
	}

	best := matchRecord(records, geoInfo)
	if best == nil {
		logger.Warn("no matching record", "domain", domain)
		m.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(m)
		return
	}

	rr := s.buildRR(domain, q.Qtype, best)
	if rr == nil {
		logger.Warn("record type mismatch", "domain", domain, "record_type", best.Type, "qtype", q.Qtype)
		m.SetRcode(r, dns.RcodeSuccess)
		w.WriteMsg(m)
		return
	}
	m.Answer = append(m.Answer, rr)
	logger.Debug("answered", "domain", domain, "answer", rr.String())
	w.WriteMsg(m)
}

// 匹配规则：优先级由高到低
// 1. 中国大陆+运营商+省份精确匹配
// 2. 中国大陆+运营商通配（省份任意）
// 3. 中国其他 (china_other)
// 4. 大洲匹配
// 5. 默认
func matchRecord(records []*models.Record, geo *geo.GeoInfo) *models.Record {
	var best *models.Record
	bestScore := -1

	for _, rec := range records {
		score := matchScore(rec, geo)
		if score > bestScore {
			bestScore = score
			best = rec
		}
	}
	return best
}

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
		// 优先级：运营商+省份 > 仅有运营商 > 仅有省份 > 全通配
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

func (s *Server) extractClientIP(r *dns.Msg, remoteAddr net.Addr) net.IP {
    // 优先 ECS
    edns := r.IsEdns0()
    if edns != nil {
        for _, opt := range edns.Option {
            if ecs, ok := opt.(*dns.EDNS0_SUBNET); ok {
                logger.Debug("using ECS IP", "ip", ecs.Address.String())
                return ecs.Address
            }
        }
    }
    // 回退源 IP
    host, _, err := net.SplitHostPort(remoteAddr.String())
    if err != nil {
        logger.Warn("failed to split remote address", "remoteAddr", remoteAddr.String(), "error", err)
        return nil
    }
    ip := net.ParseIP(host)
    logger.Debug("using source IP", "ip", ip)
    return ip
}

func (s *Server) buildRR(domain string, qtype uint16, record *models.Record) dns.RR {
    header := dns.RR_Header{
        Name:   domain,
        Rrtype: qtype,
        Class:  dns.ClassINET,
        Ttl:    uint32(record.TTL),
    }
    switch record.Type {
    case models.TypeA:
        if qtype == dns.TypeA {
            return &dns.A{Hdr: header, A: net.ParseIP(record.Value)}
        }
    case models.TypeAAAA:
        if qtype == dns.TypeAAAA {
            return &dns.AAAA{Hdr: header, AAAA: net.ParseIP(record.Value)}
        }
    case models.TypeCNAME:
        if qtype == dns.TypeCNAME {
            return &dns.CNAME{Hdr: header, Target: dns.Fqdn(record.Value)}
        }
        // 对于 A/AAAA 查询 CNAME 记录，按照标准 DNS 返回 CNAME 本身，由客户端继续解析。
        if qtype == dns.TypeA || qtype == dns.TypeAAAA {
            return &dns.CNAME{Hdr: header, Target: dns.Fqdn(record.Value)}
        }
    }
    return nil
}
