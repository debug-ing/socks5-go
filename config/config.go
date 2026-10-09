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
	Servers []Server `yaml:"servers"`
}

type Server struct {
	Name string `yaml:"name"`
	Port int    `yaml:"port"`
	Type string `yaml:"type"`
	Auth Auth   `yaml:"auth"`
}

type Auth struct {
	Status bool    `yaml:"status"`
	Users  []Users `yaml:"users"`
}

type Users struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func LoadConfig(path string) (*Config, error) {
	once.Do(func() {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			err = readErr
			return
		}

		var c Config
		if unmarshalErr := yaml.Unmarshal(data, &c); unmarshalErr != nil {
			err = unmarshalErr
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
