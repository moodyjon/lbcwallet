package wallet

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/lbryio/lbcd/chaincfg"
	"github.com/lbryio/lbcutil/hdkeychain"
)

// defaultDBTimeout specifies the timeout value when opening the wallet
// database.
var defaultDBTimeout = 10 * time.Second

// testWallet creates a test wallet and unlocks it.
func testWallet(t *testing.T) (*Wallet, func()) {
	// Set up a wallet.
	dir, err := ioutil.TempDir("", "test_wallet")
	if err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("could not cleanup test: %v", err)
		}
	}

	seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
	if err != nil {
		t.Fatalf("unable to create seed: %v", err)
	}

	passphrase := []byte("hello world")

	loader := NewLoader(
		&chaincfg.TestNet3Params, dir, true, defaultDBTimeout, 250,
	)
	w, err := loader.CreateNewWallet(passphrase, seed, time.Now())
	if err != nil {
		t.Fatalf("unable to create wallet: %v", err)
	}
	chainClient := &mockChainClient{}
	w.chainClient = chainClient
	if err := w.Unlock(passphrase, time.After(10*time.Minute)); err != nil {
		t.Fatalf("unable to unlock wallet: %v", err)
	}

	return w, cleanup
}
