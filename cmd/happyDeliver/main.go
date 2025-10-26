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
	"log"
	"os"

	"git.happydns.org/happyDeliver/internal/app"
	"git.happydns.org/happyDeliver/internal/config"
	"git.happydns.org/happyDeliver/internal/version"
)

func main() {
	fmt.Println("happyDeliver - Email Deliverability Testing Platform")
	fmt.Printf("Version: %s\n", version.Version)

	cfg, err := config.ConsolidateConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	command := flag.Arg(0)

	switch command {
	case "server":
		if err := app.RunServer(cfg); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	case "analyze":
		if err := app.RunAnalyzer(cfg, flag.Args()[1:], os.Stdin, os.Stdout); err != nil {
			log.Fatalf("Analyzer error: %v", err)
		}
	case "version":
		fmt.Println(version.Version)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("\nCommand availables:")
	fmt.Println("  happyDeliver server          - Start the API server")
	fmt.Println("  happyDeliver analyze [-json] - Analyze email from stdin and output results to terminal")
	fmt.Println("  happyDeliver version         - Print version information")
	fmt.Println("")
	flag.Usage()
}
