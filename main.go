package main

import (
	"kuro/pkg/config"
)

func main() {
	config.LoadConfig("config.toml")
}
