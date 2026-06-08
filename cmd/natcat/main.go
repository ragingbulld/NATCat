package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"natcat/internal/core"
	"natcat/internal/server"
	"natcat/web"
)

func main() {
	if len(os.Args) > 1 && isPasswordCommand(os.Args[1]) {
		changePassword(os.Args[2:])
		return
	}

	listen := flag.String("listen", "0.0.0.0:8080", "WebUI listen address")
	dataPath := flag.String("data", defaultDataPath(), "JSON data file path")
	setupUser := flag.String("setup-user", envDefault("NATCAT_SETUP_USER", "admin"), "initial admin username")
	setupPassword := flag.String("setup-password", os.Getenv("NATCAT_SETUP_PASSWORD"), "initial admin password")
	flag.Parse()

	store, generatedPassword, err := core.OpenStore(*dataPath, *setupUser, *setupPassword)
	if err != nil {
		log.Fatalf("open data store: %v", err)
	}

	manager := core.NewManager(store)
	manager.StartEnabled()
	defer manager.StopAll()

	staticFS, err := web.StaticFS()
	if err != nil {
		log.Fatalf("load web assets: %v", err)
	}

	app := server.New(store, manager, staticFS)

	fmt.Printf("NATCat Console listening on http://%s\n", *listen)
	fmt.Printf("Data file: %s\n", *dataPath)
	if generatedPassword != "" {
		fmt.Printf("Initial login: %s / %s\n", *setupUser, generatedPassword)
		fmt.Println("Set NATCAT_SETUP_PASSWORD or pass --setup-password to choose the first password.")
	}

	if err := http.ListenAndServe(*listen, app.Handler()); err != nil {
		log.Fatal(err)
	}
}

func changePassword(args []string) {
	fs := flag.NewFlagSet("password", flag.ExitOnError)
	dataPath := fs.String("data", defaultDataPath(), "JSON data file path")
	username := fs.String("user", "", "admin username, defaults to current username")
	password := fs.String("password", os.Getenv("NATCAT_ADMIN_PASSWORD"), "new admin password")
	if err := fs.Parse(args); err != nil {
		log.Fatal(err)
	}
	if *password == "" && fs.NArg() > 0 {
		*password = fs.Arg(0)
	}
	if *password == "" {
		log.Fatal("new password is required: pass --password, use a positional value, or set NATCAT_ADMIN_PASSWORD")
	}

	if err := core.ChangeAdminPassword(*dataPath, *username, *password); err != nil {
		log.Fatalf("change admin password: %v", err)
	}
	name := *username
	if name == "" {
		name = "current admin"
	}
	fmt.Printf("Password updated for %s.\n", name)
	fmt.Printf("Data file: %s\n", *dataPath)
}

func isPasswordCommand(command string) bool {
	switch command {
	case "password", "passwd", "change-password":
		return true
	default:
		return false
	}
}

func defaultDataPath() string {
	if v := os.Getenv("NATCAT_DATA"); v != "" {
		return v
	}

	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "natcat.json"
	}

	return filepath.Join(dir, "natcat", "data.json")
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
