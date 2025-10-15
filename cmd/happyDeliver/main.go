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
	"fmt"
	"log"
	"os"
)

func main() {
	fmt.Println("Mail Tester - Email Deliverability Testing Platform")
	fmt.Println("Version: 0.1.0-dev")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "server":
		log.Println("Starting API server...")
		// TODO: Start API server
	case "analyze":
		log.Println("Starting email analyzer...")
		// TODO: Start email analyzer (LMTP/pipe mode)
	case "version":
		fmt.Println("0.1.0-dev")
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("\nUsage:")
	fmt.Println("  mailtester server   - Start the API server")
	fmt.Println("  mailtester analyze  - Start the email analyzer (MDA mode)")
	fmt.Println("  mailtester version  - Print version information")
}
