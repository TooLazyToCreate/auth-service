package config

import (
	"encoding/json"
	"log"
	"os"
)

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Env         string `json:"-"`
	DatabaseUrl string `json:"-"`
	Secret      []byte `json:"-"`
	Smtp        struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Login    string `json:"login"`
		Password string `json:"password"`
		Email    string `json:"email"`
	} `json:"smtp"`
}

func MustLoad(filePath string) *Config {
	cfg := &Config{}
	data, err := os.ReadFile(filePath)
	if os.IsNotExist(err) {
		log.Fatal("Config at \"" + filePath + "\" not found.")
	}
	err = json.Unmarshal(data, cfg)
	if err != nil {
		log.Fatal("Config parsing failed with error - " + err.Error())
	}
	cfg.Env = os.Getenv("GO_ENV")
	cfg.DatabaseUrl = os.Getenv("DATABASE_URL")
	cfg.Secret = []byte(os.Getenv("SECRET"))
	return cfg
}

func WriteTemplate(filePath string) {
	data, err := json.MarshalIndent(&Config{}, "", "  ")
	if err != nil {
		log.Fatal("Config parsing failed with error - " + err.Error())
	}
	err = os.WriteFile(filePath, data, 0666)
	if err != nil {
		log.Fatal("Failed to save config tempate with error - " + err.Error())
	}
}
