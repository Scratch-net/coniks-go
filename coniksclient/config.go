package coniksclient

import (
	"fmt"
	"io/ioutil"

	"github.com/BurntSushi/toml"
	"github.com/Scratch-net/coniks-go/crypto/sign"
	"github.com/Scratch-net/coniks-go/utils"
)

// Config contains the client's configuration needed to send a request to a
// CONIKS server: the path to the server's signing public-key file
// and the actual public-key parsed from that file; the server's addresses
// for sending registration requests and other types of requests,
// respectively.
//
// Note that if RegAddress is empty, the client falls back to using Address
// for all request types.
type Config struct {
	SignPubkeyPath string `toml:"sign_pubkey_path"`

	SigningPubKey sign.PublicKey

	RegAddress string `toml:"registration_address,omitempty"`
	Address    string `toml:"address"`
}

// LoadConfig returns a client's configuration read from the given filename.
// It reads the signing public-key file and parses the actual key.
// If there is any parsing or IO-error it returns an error (and the returned
// config will be nil).
func LoadConfig(file string) (*Config, error) {
	var conf Config
	if _, err := toml.DecodeFile(file, &conf); err != nil {
		return nil, fmt.Errorf("Failed to load config: %v", err)
	}

	// load signing key
	signPath := utils.ResolvePath(conf.SignPubkeyPath, file)
	signPubKey, err := ioutil.ReadFile(signPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot read signing key: %v", err)
	}
	if len(signPubKey) != sign.PublicKeySize {
		return nil, fmt.Errorf("Signing public-key must be 32 bytes (got %d)", len(signPubKey))
	}

	conf.SigningPubKey = signPubKey

	return &conf, nil
}
