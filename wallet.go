package bmail

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/BASChain/go-account"
	"io/ioutil"
)

type Wallet interface {
	Address() Address
	MailAddress() string
	String() string
	IsOpen() bool
	Open(auth string) error
	Close()
	SaveToPath(path string) error
	Sign(v []byte) []byte
	SignObj(v interface{}) ([]byte, error)
	SetMailName(mailName string)
	AeskeyOf(peerPub []byte) ([]byte, error)
	Seeds() []byte
}

var BMWalletVersion = 1

type BMWallet struct {
	Version   int                `json:"version"`
	Addr      Address            `json:"address"`
	MailAddr  string             `json:"bmail"`
	CipherTxt string             `json:"cipher"`
	PriKey    ed25519.PrivateKey `json:"-"`
}

func NewWallet(auth string) (Wallet, error) {
	pub, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cipherTxt, err := account.EncryptSubPriKey(pri, pub, auth)
	if err != nil {
		return nil, err
	}
	obj := &BMWallet{
		Version:   BMWalletVersion,
		Addr:      ToAddress(pub),
		CipherTxt: cipherTxt,
		PriKey:    pri,
	}

	return obj, nil
}

func (bmw *BMWallet) Address() Address {
	return bmw.Addr
}
func (bmw *BMWallet) String() string {
	b, e := json.Marshal(bmw)
	if e != nil {
		return ""
	}
	return string(b)
}
func (bmw *BMWallet) IsOpen() bool {
	return bmw.PriKey != nil
}

func (bmw *BMWallet) Open(auth string) error {
	pubKey := bmw.Addr.ToPubKey()

	subKey, err := account.DecryptSubPriKey(pubKey, bmw.CipherTxt, auth)
	if err != nil {
		return err
	}
	pub := subKey.Public().(ed25519.PublicKey)
	if 0 != bytes.Compare(pubKey, pub) {
		return fmt.Errorf("authorized failed")
	}

	bmw.PriKey = subKey
	return nil
}
func (bmw *BMWallet) Close() {
	bmw.PriKey = nil
}

func (bmw *BMWallet) SaveToPath(path string) error {
	bytes, err := json.MarshalIndent(bmw, "", "\t")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, bytes, 0644)
}

func (bmw *BMWallet) Sign(v []byte) []byte {
	return ed25519.Sign(bmw.PriKey, v)
}

func (bmw *BMWallet) SignObj(v interface{}) ([]byte, error) {
	rawBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(bmw.PriKey, rawBytes), nil
}

func (bmw *BMWallet) MailAddress() string {
	return bmw.MailAddr
}

func (bmw *BMWallet) SetMailName(mailName string) {
	bmw.MailAddr = mailName
}

func (bmw *BMWallet) AeskeyOf(peerPub []byte) ([]byte, error) {
	if bmw.PriKey == nil {
		return nil, fmt.Errorf("wallet is locked")
	}
	return account.GenerateAesKey(peerPub, bmw.PriKey)
}

func (bmw *BMWallet) Seeds() []byte {
	if bmw.PriKey == nil {
		return nil
	}
	return bmw.PriKey.Seed()
}

func LoadWallet(wPath string) (Wallet, error) {
	jsonStr, err := ioutil.ReadFile(wPath)
	if err != nil {
		return nil, err
	}

	w := new(BMWallet)
	if err := json.Unmarshal(jsonStr, w); err != nil {
		return nil, err
	}
	return w, nil
}

func LoadWalletByData(jsonStr string) (Wallet, error) {
	w := new(BMWallet)
	if err := json.Unmarshal([]byte(jsonStr), w); err != nil {
		return nil, err
	}
	return w, nil
}
