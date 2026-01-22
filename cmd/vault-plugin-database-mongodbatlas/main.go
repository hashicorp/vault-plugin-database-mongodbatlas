// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	mongodbatlas "github.com/hashicorp/vault-plugin-database-mongodbatlas"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func main() {
	err := Run()
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

// Run instantiates a MongoDBAtlas object, and runs the RPC server for the plugin
func Run() error {
	dbplugin.ServeMultiplex(mongodbatlas.New)

	return nil
}
