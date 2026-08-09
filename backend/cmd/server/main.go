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

	"github.com/forgeplane-io/vaultsmith/backend/internal/authn"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
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
	loaded, err := config.LoadApplicationFromEnv()
	if err != nil {
		return err
	}
	authConfig := loaded.Auth()
	if authConfig.Mode == config.AuthModeOff {
		logStartupWarning(log.Default())
	}

	startupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var redisRuntime *authn.RedisRuntime
	if authConfig.Mode == config.AuthModeNative {
		redisRuntime, err = authn.NewRedisRuntime(authConfig.Redis)
		if err != nil {
			return err
		}
		defer redisRuntime.Close()
		if err := redisRuntime.Probe(startupContext); err != nil {
			return err
		}
	}
	authenticator, err := authn.NewAuthenticator(startupContext, authConfig, redisRuntime)
	if err != nil {
		return err
	}

	profiles := loaded.PublicProfiles()
	publicProfiles := make([]httpapi.Profile, 0, len(profiles))
	profileIDs := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		publicProfiles = append(publicProfiles, httpapi.Profile{ID: profile.ID, Label: profile.Label})
		profileIDs = append(profileIDs, profile.ID)
	}

	var authorizer *authz.Authorizer
	if authConfig.Mode == config.AuthModeNative {
		policy, policyErr := authz.LoadPolicy(authConfig.Policy.File, profileIDs)
		if policyErr != nil {
			return policyErr
		}
		authorizer, err = authz.NewAuthorizer(policy)
		if err != nil {
			return err
		}
	}

	address := os.Getenv("HTTP_ADDR")
	if address == "" {
		address = defaultAddress
	}
	api := httpapi.NewWithDependencies(publicProfiles, loaded.Executor(), httpapi.Dependencies{
		Auth:       authenticator,
		Authorizer: authorizer,
		AuthConfig: authConfig,
	})
	serverHandler := httpapi.WrapSecurity(authenticator.SessionMiddleware(api), authConfig)
	server := &http.Server{
		Addr:              address,
		Handler:           web.New(web.Files(), serverHandler),
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
