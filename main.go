package main

import (
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"

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
        // 配置加载失败时 logger 尚未初始化，使用标准 log
        log.Fatalf("failed to load config: %v", err)
    }

    // 初始化日志系统（根据配置文件中的级别）
    logger.Init(cfg.Log.Level)

    // 初始化 SQLite
    database, err := db.Open(cfg.DB.Path)
    if err != nil {
        logger.Error("failed to open database", "error", err)
        os.Exit(1)
    }
    defer database.Close()

    // 初始化 Geo 解析器
    if err := geo.Init(
        cfg.Geo.Ip2regionV4,
        cfg.Geo.Ip2regionV6,
        cfg.Cache.GeoTtlSec,
    ); err != nil {
        logger.Error("failed to init geo", "error", err)
        os.Exit(1)
    }
    defer geo.Close()

    // 启动 DNS 服务
    querier := &db.Querier{DB: database}
    dnsServer := dns.New(cfg.DNS.Listen, querier, geoResolverAdapter{})
    go func() {
        if err := dnsServer.Start(); err != nil {
            logger.Error("dns server error", "error", err)
            os.Exit(1)
        }
    }()

    // 启动 Web 管理
    webHandler := web.NewHandler(database, cfg)
    go func() {
        if err := webHandler.Start(); err != nil {
            logger.Error("web server error", "error", err)
            os.Exit(1)
        }
    }()

    logger.Info("dsdns started successfully")
    // 等待信号
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh
    logger.Info("shutting down...")
}

type geoResolverAdapter struct{}

func (g geoResolverAdapter) GetGeoInfo(ip net.IP) (*geo.GeoInfo, int) {
    return geo.GetGeoInfo(ip)
}
