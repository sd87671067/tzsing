package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
	"tzsingbox/internal/agent"
	"tzsingbox/internal/auth"
	"tzsingbox/internal/server"
	"tzsingbox/internal/store"
	"tzsingbox/web"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func run() error {
	mode := "serve"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	prefix := env("URL_PREFIX", "/monitoring")
	if !regexp.MustCompile(`^/[a-zA-Z0-9_-]{8,96}$`).MatchString(prefix) {
		return fmt.Errorf("invalid URL_PREFIX")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if mode == "health" {
		c := http.Client{Timeout: 3 * time.Second}
		r, e := c.Get("http://127.0.0.1:8080" + prefix + "/healthz")
		if e != nil {
			return e
		}
		defer r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("unhealthy")
		}
		return nil
	}
	if mode == "agent" {
		return agent.Run(ctx, env("AGENT_CONFIG", "/etc/tzsingbox/agent.json"))
	}
	db, e := store.Open(env("DB_PATH", "/data/tzsingbox.db"))
	if e != nil {
		return e
	}
	defer db.Close()
	if mode == "init-admin" {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if e != nil {
			return e
		}
		password := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
		if !auth.ValidPassword(password) {
			return fmt.Errorf("password must be 14..256 Unicode characters and at most 1024 bytes")
		}
		return db.Init(env("ADMIN_NAME", "admin"), password)
	}
	if mode == "seed-server" {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 128))
		if e != nil {
			return e
		}
		token := strings.TrimSpace(string(b))
		if len(token) != 43 {
			return fmt.Errorf("invalid token")
		}
		_, e = db.Exec("INSERT INTO servers(id,name,token) VALUES(?,?,?)", env("SERVER_ID", "local"), env("SERVER_NAME", "Local server"), auth.Digest(token))
		return e
	}
	if mode != "serve" {
		return fmt.Errorf("unknown mode")
	}
	var count int
	if e = db.QueryRow("SELECT count(*) FROM users WHERE role='admin'").Scan(&count); e != nil {
		return e
	}
	if count == 0 {
		return fmt.Errorf("initialize administrator using init-admin with password on stdin")
	}
	app := server.New(db, prefix, env("PUBLIC_ORIGIN", "https://localhost"), http.FileServer(http.FS(web.Files())))
	app.TrustedProxy = os.Getenv("TRUSTED_PROXY")
	httpServer := &http.Server{Addr: env("LISTEN", ":8080"), Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	tlsServer := &http.Server{Addr: env("AGENT_LISTEN", ":8443"), Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	errs := make(chan error, 2)
	go func() { errs <- httpServer.ListenAndServe() }()
	go func() {
		errs <- tlsServer.ListenAndServeTLS(env("TLS_CERT", "/secrets/agent.crt"), env("TLS_KEY", "/secrets/agent.key"))
	}()
	go func() {
		tick := time.NewTicker(time.Hour)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				db.Cleanup()
			}
		}
	}()
	log.Print("tzsingbox started; monitoring only")
	select {
	case <-ctx.Done():
	case e = <-errs:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(shutdown)
	tlsServer.Shutdown(shutdown)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func main() {
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
