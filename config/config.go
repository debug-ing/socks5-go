package config

import (
	"os"
	"sync"

	"go.yaml.in/yaml/v2"
)

var (
	cfg  *Config
	once sync.Once
	err  error
)

type Config struct {
	Port int
	Auth Auth
}

type Auth struct {
	Status bool
	Users  []Users
}

type Users struct {
	Username string
	Password string
}

func LoadConfig(path string) (*Config, error) {
	once.Do(func() {
		var data []byte
		data, err := os.ReadFile(path)
		if err != nil {
			return
		}

		var c Config
		err = yaml.Unmarshal(data, &c)
		if err != nil {
			return
		}

		cfg = &c
	})

	return cfg, err
}

func GetConfig() *Config {
	if cfg == nil {
		panic("config not loaded, call LoadConfig first")
	}
	return cfg
}
