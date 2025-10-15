// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
// Authors: Pierre-Olivier Mercier, et al.
//
// This program is offered under a commercial and under the AGPL license.
// For commercial licensing, contact us at <contact@happydomain.org>.
//
// For AGPL licensing:
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"git.happydns.org/happyDeliver/internal/api"
	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/receiver"
	"git.happydns.org/happyDeliver/internal/storage"
)

const version = "0.1.0-dev"

func main() {
	fmt.Println("happyDeliver - Email Deliverability Testing Platform")
	fmt.Printf("Version: %s\n", version)

	cfg, err := config.ConsolidateConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	command := flag.Arg(0)

	switch command {
	case "server":
		runServer(cfg)
	case "analyze":
		runAnalyzer(cfg)
	case "version":
		fmt.Println(version)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runServer(cfg *config.Config) {
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Initialize storage
	store, err := storage.NewStorage(cfg.Database.Type, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	log.Printf("Connected to %s database", cfg.Database.Type)

	// Create API handler
	handler := api.NewAPIHandler(store, cfg)

	// Set up Gin router
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	// Register API routes
	apiGroup := router.Group("/api")
	api.RegisterHandlers(apiGroup, handler)

	// Start server
	log.Printf("Starting API server on %s", cfg.Bind)
	log.Printf("Test email domain: %s", cfg.Email.Domain)

	if err := router.Run(cfg.Bind); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func runAnalyzer(cfg *config.Config) {
	// Parse command-line flags
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	recipientEmail := fs.String("recipient", "", "Recipient email address (optional, will be extracted from headers if not provided)")
	fs.Parse(flag.Args()[1:])

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Initialize storage
	store, err := storage.NewStorage(cfg.Database.Type, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	log.Printf("Email analyzer ready, reading from stdin...")

	// Read email from stdin
	emailData, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("Failed to read email from stdin: %v", err)
	}

	// If recipient not provided, try to extract from headers
	var recipient string
	if *recipientEmail != "" {
		recipient = *recipientEmail
	} else {
		recipient, err = receiver.ExtractRecipientFromHeaders(emailData)
		if err != nil {
			log.Fatalf("Failed to extract recipient: %v", err)
		}
		log.Printf("Extracted recipient: %s", recipient)
	}

	// Process the email
	recv := receiver.NewEmailReceiver(store, cfg)
	if err := recv.ProcessEmailBytes(emailData, recipient); err != nil {
		log.Fatalf("Failed to process email: %v", err)
	}

	log.Println("Email processed successfully")
}

func printUsage() {
	fmt.Println("\nCommand availables:")
	fmt.Println("  happyDeliver server                     - Start the API server")
	fmt.Println("  happyDeliver analyze [-recipient EMAIL] - Analyze email from stdin (MDA mode)")
	fmt.Println("  happyDeliver version                    - Print version information")
	fmt.Println("")
	flag.Usage()
}
