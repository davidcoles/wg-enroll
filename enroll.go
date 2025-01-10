package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// TODO: add timestamp
type DeviceInfo struct {
	MAC       string            `json:"mac,omitempty"`
	WireGuard string            `json:"wireguard,omitempty"`
	Hardware  string            `json:"hardware,omitempty"`
	SSH       map[string]string `json:"ssh,omitempty"`
}

// enrol <mac> <configfile> <lshw.json>
// systemctl enable wg-quick@wg0.service

// specify from command lineor something, eg.: $ <enrol-command> ssh-dss:AAAAC3NzaC1...
var keys map[string]string = map[string]string{
	//"ssh-dss": ...
	//"ecdsa-sha2-nistp256": ...
	//"ssh-ed25519": ...
	//"ssh-rsa": ...
}

func main() {

	var mac MAC

	if m, err := hex.DecodeString(os.Args[1]); err != nil {
		panic(err)
	} else {
		copy(mac[:], m)
	}

	wgpriv, wgpub := wg()

	conf := loadConf(os.Args[2])
	lshw := loadLSHW(os.Args[3])

	priv, pub := conf.keys()

	log.Println("Signing with", base64.StdEncoding.EncodeToString(pub[:]))

	var device DeviceInfo
	device.MAC = mac.String()
	device.WireGuard = wgpub.encode()
	device.Hardware = base64.RawURLEncoding.EncodeToString(lshw)
	//device.SSH = keys

	payload, err := json.Marshal(device)

	if err != nil {
		log.Fatal("payload marshal", err)
	}

	header := []byte(`{"kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"` + base64.StdEncoding.EncodeToString(pub[:]) + `"}`)
	signature := ed25519.Sign(priv, payload)

	jwt := fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(header),
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(signature),
	)

	log.Println("Registrar", conf.Registrar)
	url := conf.Registrar + mac.String()
	resp, err := http.Post(url, "application/jose", bytes.NewReader([]byte(jwt)))

	if err != nil {
		log.Fatal("POST failed", err)
	}

	defer resp.Body.Close()

	reply, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		log.Fatal("StatusCode", resp.StatusCode, string(reply))
	}

	fmt.Println(conf.conf(wgpriv, mac)) // wg0.conf
}

func loadLSHW(file string) []byte {
	p, err := os.Open(file)

	if err != nil {
		log.Fatal(err)
	}

	defer p.Close()

	lshw, err := ioutil.ReadAll(p)

	if err != nil {
		log.Fatal(err)
	}

	return lshw
}

func loadConf(file string) (w wgconf) {
	c, err := os.Open(file)

	if err != nil {
		log.Fatal(err)
	}

	defer c.Close()

	conf, err := ioutil.ReadAll(c)

	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(conf, &w)

	if err != nil {
		log.Fatal(err)
	}

	return
}

func loadSSHKey(file string) (*ed25519.PrivateKey, ed25519.PublicKey) {

	f, err := os.Open(file)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)

	if err != nil {
		log.Fatal(err)
	}

	i, err := ssh.ParseRawPrivateKey(b)

	if err != nil {
		log.Fatal(err)
	}

	priv, ok := i.(*ed25519.PrivateKey)

	if !ok {
		log.Fatal("Not an ed25519 key")
	}

	pub, ok := priv.Public().(ed25519.PublicKey)

	if !ok {
		log.Fatal("Not an ed25519 key")
	}

	return priv, pub
}

type Key [32]byte

func (k *Key) encode() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func wg() (Key, Key) {

	priv, err := Genkey()

	if err != nil {
		panic(err.Error())
	}

	pub, err := Pubkey(priv)

	if err != nil {
		panic(err.Error())
	}

	return priv, pub

}

func Genkey() (Key, error) {
	var key [32]byte

	n, err := rand.Read(key[:])

	if err != nil {
		return key, err
	}

	if n != 32 {
		return key, errors.New("Failed to read 32 bytes fron random source")
	}

	// https://cr.yp.to/ecdh.html

	key[0] &= 248
	key[30] &= 127
	key[31] |= 64

	return key, nil
}

func Pubkey(private [32]byte) ([32]byte, error) {

	var public [32]byte

	curve25519.ScalarBaseMult(&public, &private)

	x, err := curve25519.X25519(private[:], curve25519.Basepoint)

	if err != nil {
		return public, err
	}

	if len(x) != 32 {
		return public, errors.New("Key is not 32 bytes long")
	}

	copy(public[:], x[:])

	return public, nil
}

type MAC [6]byte

func (m MAC) String() string {
	return hex.EncodeToString(m[:])
}

type wgconf struct {
	SigningKey          string
	PublicKey           string
	Endpoint            string
	Prefix              netip.Prefix
	PersistentKeepalive uint16
	Registrar           string
}

func (c *wgconf) keys() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed, err := base64.StdEncoding.DecodeString(c.SigningKey)

	if err != nil {
		log.Fatal(err)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func (c *wgconf) conf(priv Key, mac MAC) string {
	var s []string

	pka := "30"

	if c.PersistentKeepalive > 0 {
		pka = strconv.Itoa(int(c.PersistentKeepalive))
	}

	addr16 := c.Prefix.Addr().As16()
	copy(addr16[10:], mac[:])
	addr := netip.AddrFrom16(addr16)

	s = append(s, "[Interface]")
	s = append(s, "PrivateKey = "+priv.String())
	s = append(s, "Address = "+addr.String())
	s = append(s, "[Peer]")
	s = append(s, "PublicKey = "+c.PublicKey)
	s = append(s, "Endpoint = "+c.Endpoint)
	s = append(s, "AllowedIPs = "+c.Prefix.Masked().String())
	s = append(s, "PersistentKeepalive = "+pka)
	s = append(s, "")
	return strings.Join(s, "\n")
}
