package config

import (
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DNS struct {
		Listen string `yaml:"listen"`
	} `yaml:"dns"`
	Web struct {
		Listen string `yaml:"listen"`
	} `yaml:"web"`
	DB struct {
		Path string `yaml:"path"`
	} `yaml:"db"`
	Geo struct {
		Ip2regionV4 string `yaml:"ip2region_v4"`
		Ip2regionV6 string `yaml:"ip2region_v6"`
	} `yaml:"geo"`
	JWT struct {
		Secret      string `yaml:"secret"`
		ExpireHours int    `yaml:"expire_hours"`
	} `yaml:"jwt"`
	Cache struct {
		GeoTtlSec int `yaml:"geo_ttl_sec"`
	} `yaml:"cache"`
	Log struct {
		Level string `yaml:"level"`
	} `yaml:"log"`
	DoH struct {
		Domain       string `yaml:"domain"`
		Managed      bool   `yaml:"managed"`
		ListenHTTP   string `yaml:"listen_http"`
		ListenHTTPS  string `yaml:"listen_https"`
		CacheDir     string `yaml:"cache_dir"`
		WelcomePage  string `yaml:"welcome_page"`
	} `yaml:"doh"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	// 默认值
	if cfg.JWT.ExpireHours == 0 {
		cfg.JWT.ExpireHours = 24
	}
	if cfg.Cache.GeoTtlSec == 0 {
		cfg.Cache.GeoTtlSec = 300
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "error"
	}
	if cfg.DoH.ListenHTTP == "" {
		cfg.DoH.ListenHTTP = ":80"
	}
	if cfg.DoH.ListenHTTPS == "" {
		cfg.DoH.ListenHTTPS = ":443"
	}
	if cfg.DoH.CacheDir == "" {
		cfg.DoH.CacheDir = "./certs"
	}
	return cfg, nil
}
