package models

import "time"

// 记录类型常量
const (
	TypeA     = "A"
	TypeAAAA  = "AAAA"
    TypeANAME = "ANAME"
)

// Rule 规则说明：
// - "default"                    默认规则（兜底）
// - "continent:asia"             大洲匹配（asia, europe, africa, north_america, south_america, oceania）
// - "china_other"                中国其他（港澳台+无法识别省份/运营商的国内IP）
// - "china:isp:mobile"           中国大陆+运营商通配
// - "china:isp:mobile:province:重庆"   中国大陆+运营商+省份精确匹配
type Rule struct {
	Type     string // "default", "continent", "china_other", "china"
	Continent string // 当 Type="continent" 时使用
	ISP       string // 当 Type="china" 时使用，可为空（表示通配运营商）
	Province  string // 当 Type="china" 时使用，可为空（表示通配省份）
	Generated  int    `json:"generated"` // 0手动, 1自动
}

// Record 存储DNS记录
type Record struct {
	ID         int64  `json:"id"`
	DomainID   int64  `json:"domain_id"`
	RuleType   string `json:"rule_type"`   // "default", "continent", "china_other", "china"
	Continent  string `json:"continent"`   // asia, europe, ...
	ISP        string `json:"isp"`         // mobile, unicom, telecom, ...
	Province   string `json:"province"`
	Type       string `json:"type"`        // A, AAAA, CNAME
	Value      string `json:"value"`
	TTL        int    `json:"ttl"`
}

// 为了方便前端序列化，提供组合字段
func (r *Record) RuleKey() string {
	switch r.RuleType {
	case "default":
		return "default"
	case "continent":
		return "continent:" + r.Continent
	case "china_other":
		return "china_other"
	case "china":
		if r.ISP == "" && r.Province == "" {
			return "china:*:*"
		} else if r.ISP != "" && r.Province == "" {
			return "china:isp:" + r.ISP
		} else {
			return "china:isp:" + r.ISP + ":province:" + r.Province
		}
	}
	return ""
}

// User, Domain 保持不变
type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	IsAdmin      bool      `json:"is_admin"`
	CreatedAt    time.Time `json:"created_at"`
}

type Domain struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Domain    string    `json:"domain"`
	CreatedAt time.Time `json:"created_at"`
}
