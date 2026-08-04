package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/httpapi"
	"github.com/forgeplane-io/vaultsmith/backend/internal/version"
	"github.com/forgeplane-io/vaultsmith/backend/web"
)

const defaultAddress = ":8080"

const startupBoundaryWarning = "Vaultsmith does not authenticate requests; run it only behind an authenticated private boundary."

func logStartupWarning(logger *log.Logger) {
	logger.Printf("WARNING: %s", startupBoundaryWarning)
}

func main() {
	showVersion := flag.Bool("version", false, "print the Vaultsmith version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	if err := run(); err != nil {
		log.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	logStartupWarning(log.Default())

	loaded, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	profiles := loaded.PublicProfiles()
	publicProfiles := make([]httpapi.Profile, 0, len(profiles))
	for _, profile := range profiles {
		publicProfiles = append(publicProfiles, httpapi.Profile{ID: profile.ID, Label: profile.Label})
	}

	address := os.Getenv("HTTP_ADDR")
	if address == "" {
		address = defaultAddress
	}
	server := &http.Server{
		Addr:              address,
		Handler:           web.New(web.Files(), httpapi.New(publicProfiles, loaded.Executor())),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("listening on %s", address)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
