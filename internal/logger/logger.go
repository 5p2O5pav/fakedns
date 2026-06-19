package logger

import (
    "log/slog"
    "os"
    "strings"
)

var Log *slog.Logger

func Init(level string) {
    var lvl slog.Level
    switch strings.ToLower(level) {
    case "debug":
        lvl = slog.LevelDebug
    case "info":
        lvl = slog.LevelInfo
    case "warn":
        lvl = slog.LevelWarn
    case "error":
        lvl = slog.LevelError
    default:
        lvl = slog.LevelInfo
    }
    opts := &slog.HandlerOptions{
        Level: lvl,
    }
    handler := slog.NewTextHandler(os.Stderr, opts)
    Log = slog.New(handler)
    slog.SetDefault(Log)
}

func Debug(msg string, args ...any) { Log.Debug(msg, args...) }
func Info(msg string, args ...any)  { Log.Info(msg, args...) }
func Warn(msg string, args ...any)  { Log.Warn(msg, args...) }
func Error(msg string, args ...any) { Log.Error(msg, args...) }
