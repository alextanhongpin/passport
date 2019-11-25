package database

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	Password string `envconfig:"DB_PASS"`
	User     string `envconfig:"DB_USER"`
	Database string `envconfig:"DB_NAME"`
	Host     string `envconfig:"DB_HOST"`
	Port     int    `envconfig:"DB_PORT"`
}

func NewConfig() (*Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	return &cfg, err
}

func (c *Config) String() string {
	return fmt.Sprintf("dbname=%s user=%s password=%s host=%s port=%d sslmode=disable",
		c.Database,
		c.User,
		c.Password,
		c.Host,
		c.Port)
}
