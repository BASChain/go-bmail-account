package bmail

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	return bmw.PriKey == nil
}

func (bmw *BMWallet) Open(auth string) error {
	subKey, err := account.DecryptSubPriKey(bmw.Addr.ToPubKey(), bmw.CipherTxt, auth)
	if err != nil {
		return err
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
