package main

import (
	cfg "github.com/conductorone/baton-jamf/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("jamf", cfg.Config)
}
