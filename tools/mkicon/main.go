// Command mkicon writes the executable's icon file for go-winres.
package main

import (
	"log"
	"os"

	"splitwire/internal/tray"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: mkicon <out.ico>")
	}
	if err := os.WriteFile(os.Args[1], tray.AppIcon(), 0o644); err != nil {
		log.Fatal(err)
	}
}
