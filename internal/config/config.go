package config

import (
	"log/slog"
	"os"

	"github.com/BurntSushi/toml"
)

type ServerConfig struct {
	Url string `toml:"server_url"`
}

type Config struct {
	Server ServerConfig `toml:"server"`
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{Url: "http://localhost:8080"}
}

func DefaultConfig() Config {
	server := DefaultServerConfig()
	return Config{Server: server}
}

func LoadConfig(path string) (cfg Config, found bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		slog.Warn(
			"Cannot open config file. Loading default config",
			slog.String("error", err.Error()),
		)
		return DefaultConfig(), false
	}
	_, err = toml.Decode(string(data), &cfg)
	if err != nil {
		slog.Warn(
			"Cannot decode config file. Loading default config",
			slog.String("error", err.Error()),
		)
		return DefaultConfig(), false
	}
	return cfg, true
}

func (c Config) SaveConfig(path string) error {
	raw, err := toml.Marshal(c)
	if err != nil {
		slog.Warn(
			"Cannot decode config file.",
			slog.String("error", err.Error()),
		)
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		slog.Warn(
			"Cannot save config file.",
			slog.String("error", err.Error()),
		)
		return err
	}
	defer f.Close()

	_, err = f.Write(raw)
	if err != nil {
		slog.Warn(
			"Cannot write config file.",
			slog.String("error", err.Error()),
		)
		return err
	}
	return nil
}

func ConfigInit() Config {
	path := GetConfigPath()
	cfg, found := LoadConfig(path)
	if !found {
		cfg.SaveConfig(path)
	}
	return cfg
}

func GetConfigPath() string {
	path := os.Getenv("SCHAT_CONFIG")
	if path == "" {
		path = "./secure_chat.toml"
	}
	return path
}
