package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/decred/dcrd/txscript"
	"github.com/decred/dcrd/wire"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainec"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/rpcclient"
	"github.com/decred/dcrd/rpctest"

	"github.com/decred/dcrwallet/chain"
	"github.com/decred/dcrwallet/errors"
	walletloader "github.com/decred/dcrwallet/loader"
	base "github.com/decred/dcrwallet/wallet"
	"github.com/decred/dcrwallet/wallet/txrules"
)

var (
	netParams    = &chaincfg.SimNetParams
	nullArray    = [128]byte{}
	walletSynced bool
	feeRate      = dcrutil.Amount(1e4)
)

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func fatalf(msg string, args ...interface{}) {
	panic(fmt.Errorf(msg, args...))
}

func logf(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	fmt.Printf("\n")
}

func waitForMempoolTx(r *rpctest.Harness, txid *chainhash.Hash) error {
	var found bool
	var tx *dcrutil.Tx
	var err error
	timeout := time.After(30 * time.Second)
	for !found {
		// Do a short wait
		select {
		case <-timeout:
			return fmt.Errorf("timeout after 10s")
		default:
		}
		time.Sleep(100 * time.Millisecond)

		// Check for the harness' knowledge of the txid
		tx, err = r.Node.GetRawTransaction(txid)
		if err != nil {
			switch e := err.(type) {
			case *dcrjson.RPCError:
				if e.Code == dcrjson.ErrRPCNoTxInfo {
					continue
				}
			default:
			}
			return err
		}
		if tx != nil && tx.MsgTx().TxHash() == *txid {
			found = true
		}
	}
	return nil
}

func mineAndAssertTxInBlock(miner *rpctest.Harness, txid chainhash.Hash) error {

	// First, we'll wait for the transaction to arrive in the mempool.
	if err := waitForMempoolTx(miner, &txid); err != nil {
		return fmt.Errorf("unable to find %v in the mempool: %v", txid, err)
	}

	// We'll mined a block to confirm it.
	blockHashes, err := miner.Node.Generate(1)
	if err != nil {
		return fmt.Errorf("unable to generate new block: %v", err)
	}

	// Finally, we'll check it was actually mined in this block.
	block, err := miner.Node.GetBlock(blockHashes[0])
	if err != nil {
		return fmt.Errorf("unable to get block %v: %v", blockHashes[0], err)
	}
	if len(block.Transactions) != 2 {
		return fmt.Errorf("expected 2 transactions in block, found %d",
			len(block.Transactions))
	}
	txHash := block.Transactions[1].TxHash()
	if txHash != txid {
		return fmt.Errorf("expected transaction %v to be mined, found %v", txid,
			txHash)
	}

	return nil
}

func manualWalletTx(wallet *base.Wallet, pkScript []byte, srcTx *wire.MsgTx,
	signPk chainec.PrivateKey) *wire.MsgTx {

	txFee := dcrutil.Amount(1e4) // dummy fee
	outputValue := dcrutil.Amount(dcrutil.AtomsPerCoin) - txFee

	// Find the output index we'll spend from. Assume it has the same pkScript
	// as the one we'll spend to.
	var outputIndex uint32
	if len(srcTx.TxOut) == 1 || bytes.Equal(srcTx.TxOut[0].PkScript, pkScript) {
		outputIndex = 0
	} else {
		outputIndex = 1
	}

	tx1 := wire.NewMsgTx()
	tx1.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  srcTx.TxHash(),
			Index: outputIndex,
			Tree:  wire.TxTreeRegular,
		},
		// We don't support RBF, so set sequence to max.
		Sequence: wire.MaxTxInSequenceNum,
	})
	tx1.AddTxOut(&wire.TxOut{
		Value:    int64(outputValue),
		PkScript: pkScript,
		Version:  txscript.DefaultScriptVersion,
	})

	sig, err := txscript.SignatureScript(tx1,
		0, pkScript, txscript.SigHashAll, signPk, true)
	orPanic(err)
	tx1.TxIn[0].SignatureScript = sig

	return tx1
}

func onRpcSyncerSynced(synced bool) {
	logf("RPC Syncer synced")
	walletSynced = true
}

func test(wallet *base.Wallet, miningNode *rpctest.Harness) {
	addr, err := wallet.NewExternalAddress(0)
	orPanic(err)
	time.Sleep(time.Second)

	// Fund the wallet
	pkScript, err := txscript.PayToAddrScript(addr)
	orPanic(err)
	fundingOut := wire.TxOut{
		PkScript: pkScript,
		Value:    int64(100 * dcrutil.AtomsPerCoin), // value must be higher than nbAttempts.
	}
	_, err = miningNode.SendOutputs([]*wire.TxOut{&fundingOut}, feeRate)
	orPanic(err)

	_, err = miningNode.Node.Generate(2)
	orPanic(err)

	time.Sleep(time.Second)

	balances, err := wallet.CalculateAccountBalance(0, 0)
	orPanic(err)
	fmt.Printf("Wallet balance: %s\n", balances.Total)

	// Wallet is now funded. Do a set of trial runs.
	//
	// vvvvvvv this is where testing actually begins vvvvvvv

	// Setup some aux stuff.

	testOut := wire.TxOut{
		PkScript: pkScript,
		Value:    dcrutil.AtomsPerCoin,
	}
	nbAttempts := 10
	netBackend, err := wallet.NetworkBackend()
	orPanic(err)

	// Get the private key for signing `addr`. We'll manually sign using that
	// instead of offloading signing to the wallet.
	signWifStr, err := wallet.DumpWIFPrivateKey(addr)
	orPanic(err)
	signWif, err := dcrutil.DecodeWIF(signWifStr)
	orPanic(err)
	signPk := signWif.PrivKey

	for i := 0; i < nbAttempts; i++ {

		fmt.Printf("Trial run %d/%d\n", i+1, nbAttempts)

		// Create the first tx spending funds from the wallet (this already
		// publishes the tx).
		srcTxId, err := wallet.SendOutputs([]*wire.TxOut{&testOut}, 0, 0)
		orPanic(err)
		srcTxs, _, err := wallet.GetTransactionsByHashes([]*chainhash.Hash{srcTxId})
		orPanic(err)
		srcTx := srcTxs[0]

		// Wait for this tx to hit the mining node's mempool.
		err = waitForMempoolTx(miningNode, srcTxId)
		orPanic(err)

		// Mine a block containing this tx
		err = mineAndAssertTxInBlock(miningNode, *srcTxId)
		orPanic(err)

		// Manually create a second tx spending from srcTx (this already
		// signs the tx, without hitting the wallet for anything).
		tx1 := manualWalletTx(wallet, pkScript, srcTx, signPk)

		// Manually publish this transaction through the wallet.
		serTx1, err := tx1.Bytes()
		orPanic(err)
		_, err = wallet.PublishTransaction(tx1, serTx1, netBackend)
		orPanic(err)

		// Wait for it to hit the mempool
		txid1 := tx1.TxHash()
		err = waitForMempoolTx(miningNode, &txid1)
		orPanic(err)

		// Publish the transaction a second time (this should error with
		// "already have transaction", but that's fine).
		//
		// What is _not_ fine is erroring out with a "output ... referenced
		// from transaction either does not exist or has already been spent".
		_, err = wallet.PublishTransaction(tx1, serTx1, netBackend)
		if err != nil {
			if strings.Contains(err.Error(), "already have transaction") {
				fmt.Println("   already had transaction")
			} else {
				orPanic(err)
			}
		}

		// Generate a block
		_, err = miningNode.Node.Generate(1)
		orPanic(err)

	}
}

func main() {
	// Create the rpctest harness main node.
	miningNode, err := rpctest.New(netParams, nil, []string{"--txindex"})
	if err != nil {
		fatalf("unable to create mining node: %v", err)
	}
	logf("mining node created")

	if err := miningNode.SetUp(true, 25); err != nil {
		fatalf("unable to set up mining node: %v", err)
	}
	logf("mining node setup")
	defer miningNode.TearDown()

	// Create the chain.RPCClient that we'll use to connect to the wallet
	rpcConfig := miningNode.RPCConfig()
	walletRpcClient, err := chain.NewRPCClient(netParams,
		rpcConfig.Host, rpcConfig.User, rpcConfig.Pass,
		rpcConfig.Certificates, false)
	if err != nil {
		fatalf("unable to make chain rpc: %v", err)
	}
	logf("wallet RPCClient created")

	// Create the new test wallet
	tempTestDir, err := ioutil.TempDir("", "test-wallet")
	if err != nil {
		fatalf("unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempTestDir)
	loader := walletloader.NewLoader(netParams, tempTestDir,
		&walletloader.StakeOptions{}, base.DefaultGapLimit, false,
		txrules.DefaultRelayFeePerKb.ToCoin(), base.DefaultAccountGapLimit)

	wallet, err := loader.CreateNewWallet([]byte("public"), []byte("private"),
		nullArray[:64])
	if err != nil {
		panic(err)
	}
	logf("wallet created")

	if err := wallet.Unlock([]byte("private"), nil); err != nil {
		panic(err)
	}
	logf("wallet unlocked")

	err = walletRpcClient.Start(context.TODO(), true)
	if err != nil && !errors.MatchAll(rpcclient.ErrClientAlreadyConnected, err) {
		panic(err)
	}
	logf("wallet rpcclient started")

	walletNetBackend := chain.BackendFromRPCClient(walletRpcClient.Client)
	wallet.SetNetworkBackend(walletNetBackend)

	go func() {
		logf("Starting syncer...")
		syncer := chain.NewRPCSyncer(wallet, walletRpcClient)
		syncer.SetNotifications(&chain.Notifications{
			Synced: onRpcSyncerSynced,
		})
		ctx := context.TODO()
		err := syncer.Run(ctx, true)

		if err != nil {
			logf("error after syncer.run: %v", err)
		}
	}()

	ticker := time.NewTicker(1000 * time.Millisecond)
	for range ticker.C {
		if walletSynced {
			break
		}
	}
	ticker.Stop()

	test(wallet, miningNode)

	logf("Done!")
}
