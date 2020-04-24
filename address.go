package bmail

import (
	"crypto/ed25519"
	"github.com/btcsuite/btcutil/base58"
)

const (
	AccPrefix = "BM"
	AccIDLen  = 40
)

type Address string

func (addr Address) String() string {
	return string(addr)
}

func (addr Address) ToPubKey() ed25519.PublicKey {
	if len(addr) <= len(AccPrefix) {
		return nil
	}
	ss := string(addr[len(AccPrefix):])
	return base58.Decode(ss)
}

func (addr Address) IsValid() bool {
	if len(addr) <= AccIDLen {
		return false
	}
	if addr[:len(AccPrefix)] != AccPrefix {
		return false
	}
	if len(addr.ToPubKey()) != ed25519.PublicKeySize {
		return false
	}
	return true
}

func ToAddress(key []byte) Address {
	return Address(AccPrefix + base58.Encode(key))
}
