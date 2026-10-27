package main

import (
	"os"

	"github.com/tal7aouy/php2shell-scanner/internal/cli"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)) }
