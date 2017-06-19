package hasher

import (
	"crypto"

	ccrypto "github.com/coniks-sys/coniks-go/crypto"
	"github.com/coniks-sys/coniks-go/utils"
)

const (
	emptyIdentifier = 'E'
	leafIdentifier  = 'L'
)

// Hash represents the output of the used hash function.
type Hash [ccrypto.DefaultHashSizeByte]byte

// PADHasher provides hash functions for the PAD implementations.
type PADHasher interface {
	ID() string
	Size() int
	Digest(ms ...[]byte) []byte
	TreeHasher
}

// TreeHasher provides hash functions for tree implementations.
type TreeHasher interface {
	HashInterior(left, right []byte) []byte
	HashLeaf(nonce []byte, index []byte, level uint32, data []byte) []byte
	HashEmpty(nonce []byte, index []byte, level uint32) []byte
}

type coniksHasher struct {
	crypto.Hash
}

// New creates a new PADHasher using the passed in hash function.
func New(h crypto.Hash) PADHasher {
	return &coniksHasher{Hash: h}
}

// Default is the standard CONIKS hasher.
func Default() PADHasher {
	return New(crypto.SHA512_256)
}

// Digest hashes all passed byte slices.
// The passed slices won't be mutated.
func (ch *coniksHasher) Digest(ms ...[]byte) []byte {
	h := ch.New()
	for _, m := range ms {
		h.Write(m)
	}
	return h.Sum(nil)
}

// ID returns the name of the cryptographic hash function in string.
func (coniksHasher) ID() string {
	return "SHA-512/256"
}

// Size returns the size of the hash output in bytes.
func (ch *coniksHasher) Size() int {
	return ch.Size()
}

// HashInterior computes the hash of an interior node:
// H(left || right)
func (ch *coniksHasher) HashInterior(left, right []byte) []byte {
	return ch.Digest(left, right)
}

// HashLeaf computes the hash of a user leaf node:
// H(Identifier || nonce || index || level || commit)
func (ch *coniksHasher) HashLeaf(nonce []byte, index []byte, level uint32, commit []byte) []byte {
	return ch.Digest(
		[]byte{leafIdentifier},
		nonce,
		index,
		utils.UInt32ToBytes(level),
		commit,
	)
}

// HashEmpty computes the hash of an empty leaf node:
// H(Identifier || nonce || index || level)
func (ch *coniksHasher) HashEmpty(nonce []byte, index []byte, level uint32) []byte {
	return ch.Digest(
		[]byte{emptyIdentifier},
		nonce,
		index,
		utils.UInt32ToBytes(level),
	)
}
