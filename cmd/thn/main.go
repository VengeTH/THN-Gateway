// Command thn is the THN gateway control CLI.
//
// # Safety tiers
//
// thn separates its commands by what they need:
//
//	thn validate     pure   — in-process, no daemon, no root
//	thn plan         pure   — in-process, no daemon, no root
//	thn config       pure   — in-process, no daemon, no root
//	thn schema       pure   — in-process, no daemon, no root
//	thn status       live   — requires thnd (or --local)
//	thn diagnostics  live   — requires thnd (or --local)
//	thn activate     destructive — changes host networking with confirmation and presence
//
// The pure commands are safe to run unattended, including in CI, on a
// development machine, or against a production gateway. They cannot change
// host networking: they never reach a privileged operation, and every host
// command they might run is read-only and checked by internal/guard.
package main

import (
	"os"

	"github.com/VengeTH/THN-Gateway/internal/cli"
)

func main() {
	os.Exit(int(cli.Run(cli.NewEnv(os.Args[1:]))))
}
