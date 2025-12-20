package main

import (
	"log"
	"log/slog"

	"kuro/data"
	"kuro/loader"
)

// ConvertToSpecs  TODO: move this function to another package

func main() {
	slog.SetLogLoggerLevel(slog.LevelInfo)

	manager := loader.NewEbpfManager()
	defer manager.Close()

	hostName := "hostA"
	if err := data.RunDataClient("127.0.0.1:50051", hostName, "", []string{}, "", manager); err != nil {
		log.Fatalf("Data client stopped with error: %v", err)
	}
}
