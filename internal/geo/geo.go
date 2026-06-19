package geo

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"github.com/patrickmn/go-cache"
	"dsdns/internal/logger"
)

type GeoInfo struct {
	Country      string
	CountryCode  string
	Province     string
	City         string
	ISP          string
	Continent    string
	IsChina      bool
	IsMainland   bool
	IsHongKong   bool
	IsMacau      bool
	IsTaiwan     bool
}

type Resolver struct {
	v4Searcher *xdb.Searcher
	v6Searcher *xdb.Searcher
	cache      *cache.Cache
	mu         sync.RWMutex
}

var global *Resolver
var once sync.Once

func Init(v4DB, v6DB string, cacheTTL int) error {
	var err error
	once.Do(func() {
		logger.Info("[geo] Init", "v4DB", v4DB, "v6DB", v6DB)
		r := &Resolver{
			cache: cache.New(time.Duration(cacheTTL)*time.Second, time.Minute),
		}
		if v4DB != "" {
			r.v4Searcher, err = newSearcher(v4DB)
			if err != nil {
				err = fmt.Errorf("init IPv4 searcher: %w", err)
				return
			}
		}
		if v6DB != "" {
			r.v6Searcher, err = newSearcher(v6DB)
			if err != nil {
				logger.Warn("[geo] IPv6 searcher init failed", "error", err)
				r.v6Searcher = nil
			}
		}
		global = r
	})
	return err
}

func newSearcher(dbPath string) (*xdb.Searcher, error) {
	cBuff, err := xdb.LoadContentFromFile(dbPath)
	if err != nil {
		return nil, err
	}
	header, err := xdb.LoadHeaderFromBuff(cBuff)
	if err != nil {
		return nil, err
	}
	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, err
	}
	return xdb.NewWithBuffer(version, cBuff)
}

func GetGeoInfo(ip net.IP) (*GeoInfo, int) {
	if global == nil {
		logger.Error("[geo] not initialized")
		return &GeoInfo{}, 1
	}
	ipStr := ip.String()
	if cached, found := global.cache.Get(ipStr); found {
		return cached.(*GeoInfo), 1
	}
	info := global.lookup(ip)
	global.cache.SetDefault(ipStr, info)
	return info, 1
}

func (r *Resolver) lookup(ip net.IP) *GeoInfo {
	isV4 := ip.To4() != nil
	ipStr := ip.String()
	var searcher *xdb.Searcher
	if isV4 {
		searcher = r.v4Searcher
	} else {
		searcher = r.v6Searcher
	}
	if searcher == nil {
		return &GeoInfo{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	regionStr, err := searcher.Search(ipStr)
	if err != nil {
		logger.Error("[geo] search error", "ip", ipStr, "error", err)
		return &GeoInfo{}
	}
	return parseRegionToGeoInfo(regionStr)
}

func parseRegionToGeoInfo(regionStr string) *GeoInfo {
    parts := strings.Split(regionStr, "|")
    if len(parts) < 5 {
        return &GeoInfo{}
    }
    country := parts[0]
    province := parts[1]
    city := parts[2]
    isp := parts[3]
    code := parts[4]

    info := &GeoInfo{
        Country:     country,
        CountryCode: code,
        Province:    province,
        City:        city,
        ISP:         normalizeISP(isp),
        Continent:   "", // 默认为空
    }

    if country == "中国" || strings.HasPrefix(country, "中国") {
        info.IsChina = true
        // 港澳台判断...
        if province == "香港" || city == "香港" || code == "HK" {
            info.IsHongKong = true
            return info
        }
        // 澳门、台湾类似...
        info.IsMainland = true
        return info
    }

    // 非中国，根据国家代码映射大洲
    info.Continent = countryCodeToContinent(code)
    return info
}

func normalizeISP(isp string) string {
	low := strings.ToLower(isp)
	switch {
	case strings.Contains(low, "移动"):
		return "mobile"
	case strings.Contains(low, "联通"):
		return "unicom"
	case strings.Contains(low, "电信"):
		return "telecom"
	case strings.Contains(low, "广电"):
		return "broadcast"
	case strings.Contains(low, "教育"):
		return "education"
	default:
		return "other"
	}
}

func countryCodeToContinent(code string) string {
	m := map[string]string{
		"AD": "EU", "AE": "AS", "AF": "AS", "AG": "NA", "AI": "NA", "AL": "EU", "AM": "AS", "AO": "AF",
		"AQ": "AN", "AR": "SA", "AS": "OC", "AT": "EU", "AU": "OC", "AW": "NA", "AX": "EU", "AZ": "AS",
		"BA": "EU", "BB": "NA", "BD": "AS", "BE": "EU", "BF": "AF", "BG": "EU", "BH": "AS", "BI": "AF",
		"BJ": "AF", "BL": "NA", "BM": "NA", "BN": "AS", "BO": "SA", "BQ": "NA", "BR": "SA", "BS": "NA",
		"BT": "AS", "BV": "AN", "BW": "AF", "BY": "EU", "BZ": "NA", "CA": "NA", "CC": "AS", "CD": "AF",
		"CF": "AF", "CG": "AF", "CH": "EU", "CI": "AF", "CK": "OC", "CL": "SA", "CM": "AF", "CN": "AS",
		"CO": "SA", "CR": "NA", "CU": "NA", "CV": "AF", "CW": "NA", "CX": "AS", "CY": "EU", "CZ": "EU",
		"DE": "EU", "DJ": "AF", "DK": "EU", "DM": "NA", "DO": "NA", "DZ": "AF", "EC": "SA", "EE": "EU",
		"EG": "AF", "EH": "AF", "ER": "AF", "ES": "EU", "ET": "AF", "FI": "EU", "FJ": "OC", "FK": "SA",
		"FM": "OC", "FO": "EU", "FR": "EU", "GA": "AF", "GB": "EU", "GD": "NA", "GE": "AS", "GF": "SA",
		"GG": "EU", "GH": "AF", "GI": "EU", "GL": "NA", "GM": "AF", "GN": "AF", "GP": "NA", "GQ": "AF",
		"GR": "EU", "GS": "AN", "GT": "NA", "GU": "OC", "GW": "AF", "GY": "SA", "HK": "AS", "HM": "AN",
		"HN": "NA", "HR": "EU", "HT": "NA", "HU": "EU", "ID": "AS", "IE": "EU", "IL": "AS", "IM": "EU",
		"IN": "AS", "IO": "AS", "IQ": "AS", "IR": "AS", "IS": "EU", "IT": "EU", "JE": "EU", "JM": "NA",
		"JO": "AS", "JP": "AS", "KE": "AF", "KG": "AS", "KH": "AS", "KI": "OC", "KM": "AF", "KN": "NA",
		"KP": "AS", "KR": "AS", "KW": "AS", "KY": "NA", "KZ": "AS", "LA": "AS", "LB": "AS", "LC": "NA",
		"LI": "EU", "LK": "AS", "LR": "AF", "LS": "AF", "LT": "EU", "LU": "EU", "LV": "EU", "LY": "AF",
		"MA": "AF", "MC": "EU", "MD": "EU", "ME": "EU", "MF": "NA", "MG": "AF", "MH": "OC", "MK": "EU",
		"ML": "AF", "MM": "AS", "MN": "AS", "MO": "AS", "MP": "OC", "MQ": "NA", "MR": "AF", "MS": "NA",
		"MT": "EU", "MU": "AF", "MV": "AS", "MW": "AF", "MX": "NA", "MY": "AS", "MZ": "AF", "NA": "AF",
		"NC": "OC", "NE": "AF", "NF": "OC", "NG": "AF", "NI": "NA", "NL": "EU", "NO": "EU", "NP": "AS",
		"NR": "OC", "NU": "OC", "NZ": "OC", "OM": "AS", "PA": "NA", "PE": "SA", "PF": "OC", "PG": "OC",
		"PH": "AS", "PK": "AS", "PL": "EU", "PM": "NA", "PN": "OC", "PR": "NA", "PS": "AS", "PT": "EU",
		"PW": "OC", "PY": "SA", "QA": "AS", "RE": "AF", "RO": "EU", "RS": "EU", "RU": "EU", "RW": "AF",
		"SA": "AS", "SB": "OC", "SC": "AF", "SD": "AF", "SE": "EU", "SG": "AS", "SH": "AF", "SI": "EU",
		"SJ": "EU", "SK": "EU", "SL": "AF", "SM": "EU", "SN": "AF", "SO": "AF", "SR": "SA", "SS": "AF",
		"ST": "AF", "SV": "NA", "SX": "NA", "SY": "AS", "SZ": "AF", "TC": "NA", "TD": "AF", "TF": "AN",
		"TG": "AF", "TH": "AS", "TJ": "AS", "TK": "OC", "TL": "AS", "TM": "AS", "TN": "AF", "TO": "OC",
		"TR": "AS", "TT": "NA", "TV": "OC", "TZ": "AF", "UA": "EU", "UG": "AF", "UM": "OC", "US": "NA",
		"UY": "SA", "UZ": "AS", "VA": "EU", "VC": "NA", "VE": "SA", "VG": "NA", "VI": "NA", "VN": "AS",
		"VU": "OC", "WF": "OC", "WS": "OC", "YE": "AS", "YT": "AF", "ZA": "AF", "ZM": "AF", "ZW": "AF",
	}
	if cont, ok := m[code]; ok {
		switch cont {
		case "AS": return "asia"
		case "EU": return "europe"
		case "AF": return "africa"
		case "NA": return "north_america"
		case "SA": return "south_america"
		case "OC": return "oceania"
		default: return ""
		}
	}
	return ""
}

func Close() {
	if global != nil {
		if global.v4Searcher != nil {
			global.v4Searcher.Close()
		}
		if global.v6Searcher != nil {
			global.v6Searcher.Close()
		}
	}
}
