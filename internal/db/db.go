package db

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// 连接池设置（sqlite 单写，这里只做保守配置）
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(time.Hour)

	if _, err := db.Exec(pragmas); err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return db, nil
}
