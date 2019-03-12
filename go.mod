module main

require (
	github.com/decred/dcrd v1.3.0
	github.com/decred/dcrd/chaincfg v1.3.0
	github.com/decred/dcrd/chaincfg/chainhash v1.0.1
	github.com/decred/dcrd/dcrec v0.0.0-20190130161649-59ed4247a1d5
	github.com/decred/dcrd/dcrjson v1.1.0
	github.com/decred/dcrd/dcrutil v1.2.0
	github.com/decred/dcrd/rpcclient v1.1.0
	github.com/decred/dcrd/txscript v1.0.2
	github.com/decred/dcrd/wire v1.2.0
	github.com/decred/dcrwallet v1.2.2
	github.com/decred/dcrwallet/chain v1.1.1
	github.com/decred/dcrwallet/errors v1.0.1
	github.com/decred/dcrwallet/wallet v1.1.0
	github.com/kr/pty v1.1.3 // indirect
)

replace github.com/decred/dcrd => github.com/matheusd/dcrd v0.0.0-20190307112912-88f09e6147f9
