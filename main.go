package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"dsdns/internal/config"
	"dsdns/internal/db"
	"dsdns/internal/dns"
	"dsdns/internal/geo"
	"dsdns/internal/logger"
	"dsdns/internal/web"
)

func main() {
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger.Init(cfg.Log.Level)

	// 初始化数据库
	database, err := db.Open(cfg.DB.Path)
	if err != nil {
		logger.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	// 初始化 Geo
	if err := geo.Init(cfg.Geo.Ip2regionV4, cfg.Geo.Ip2regionV6, cfg.Cache.GeoTtlSec); err != nil {
		logger.Error("failed to init geo", "error", err)
		os.Exit(1)
	}
	defer geo.Close()

	// ---- 启动管理面板（内部端口） ----
	webHandler := web.NewHandler(database, cfg)
	go func() {
		logger.Info("Management panel listening", "addr", cfg.Web.Listen)
		if err := http.ListenAndServe(cfg.Web.Listen, webHandler.Router()); err != nil {
			logger.Error("web server error", "error", err)
		}
	}()

	// ---- 启动 DoH/伪装服务器 ----
	dohDomain := cfg.DoH.Domain
	if dohDomain == "" {
		logger.Error("DoH domain not set")
		os.Exit(1)
	}

	// 创建 DoH 服务器（包含 ANAME 管理）
	querier := &db.Querier{DB: database}
	geoResolver := geoResolverAdapter{}
	dohSrv := dns.NewDoHServer(querier, geoResolver, dohDomain, database) // 需要扩展构造函数

	// 扩展 DoHServer 构造函数，增加 db 参数用于 ANAME 管理
	// 我们修改 NewDoHServer 为：
	// func NewDoHServer(dbQuerier DBQuerier, geo GeoResolver, domain string, db *sql.DB) *DoHServer

	// 启动 ANAME 后台同步
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	anameMgr := dns.NewANAMEManager(database)
	anameMgr.Start(ctx)

	// 配置 HTTPS 服务器
	httpsSrv := &http.Server{
		Addr:    cfg.DoH.ListenHTTPS,
		Handler: dohSrv,
	}

	var tlsConfig *tls.Config
	if cfg.DoH.Managed {
		// 使用 Let's Encrypt 自动证书
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(dohDomain),
			Cache:      autocert.DirCache(cfg.DoH.CacheDir),
		}
		tlsConfig = &tls.Config{
			GetCertificate: certManager.GetCertificate,
		}
		// 同时启动 HTTP 重定向服务（用于验证）
		go func() {
			redirect := http.NewServeMux()
			redirect.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+r.Host+r.URL.Path, http.StatusMovedPermanently)
			})
			logger.Info("HTTP redirect server listening", "addr", cfg.DoH.ListenHTTP)
			if err := http.ListenAndServe(cfg.DoH.ListenHTTP, redirect); err != nil {
				logger.Error("HTTP redirect server error", "error", err)
			}
		}()
	} else {
		// 用户自行提供证书，从配置中读取路径（需在 config 中增加 cert_file 和 key_file）
		// 此处简化，若未 managed 则直接启动 TLS 但证书路径未配置，实际应增加配置项
		// 我们增加 DoH.CertFile 和 DoH.KeyFile 到配置
		// 为简化演示，这里仅处理 managed 模式
		logger.Error("non-managed TLS not implemented in this demo")
		os.Exit(1)
	}

	httpsSrv.TLSConfig = tlsConfig
	go func() {
		logger.Info("DoH/nginx伪装服务器 listening", "addr", cfg.DoH.ListenHTTPS)
		if err := httpsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTPS server error", "error", err)
		}
	}()

	logger.Info("ddns-faker started successfully")

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutting down...")
	cancel()
	ctxShutdown, _ := context.WithTimeout(context.Background(), 5*time.Second)
	httpsSrv.Shutdown(ctxShutdown)
}

type geoResolverAdapter struct{}

func (g geoResolverAdapter) GetGeoInfo(ip net.IP) (*geo.GeoInfo, int) {
	return geo.GetGeoInfo(ip)
}
