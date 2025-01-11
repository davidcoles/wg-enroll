package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// TODO: add timestamp
type DeviceInfo struct {
	MAC       string            `json:"mac,omitempty"`
	WireGuard string            `json:"wireguard,omitempty"`
	Lshw      string            `json:"lshw,omitempty"`  // lshw -json
	Lspci     string            `json:"lspci,omitempty"` // lspci -vvnn
	SSH       map[string]string `json:"ssh,omitempty"`   // $(cat /etc/ssh/*.pub | sed 's/ /:/g' | cut -d: -f1-2)
}

// enrol <mac> <configfile> <lshw.json>
// systemctl enable wg-quick@wg0.service

// -lshw
// -lspci
// $(cat /etc/ssh/*.pub | sed 's/ /:/g' | cut -d: -f1-2)

var lshw = flag.String("lshw", "", "lshw -json")
var lspci = flag.String("lspci", "", "lspci -vvnn")

func main() {

	var mac MAC

	flag.Parse()
	args := flag.Args()

	if m, err := hex.DecodeString(args[0]); err != nil {
		panic(err)
	} else {
		copy(mac[:], m)
	}

	conf := loadConf(args[1])
	keys := args[2:]

	wgpriv, wgpub := wg()

	priv, pub := conf.keys()

	log.Println("Signing with", base64.StdEncoding.EncodeToString(pub[:]))

	var device DeviceInfo
	device.MAC = mac.String()
	device.WireGuard = wgpub.encode()
	device.Lshw = loadFile(*lshw)
	device.Lspci = loadFile(*lspci)
	device.SSH = map[string]string{}

	re := regexp.MustCompile("^([-a-z0-9]+):([-+_=/a-zA-Z0-9]+)$")

	for _, k := range keys {
		m := re.FindStringSubmatch(k)
		if len(m) != 3 {
			log.Fatal("Funny looking SSH key - ", k)
		}

		device.SSH[m[1]] = m[2]
	}

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

func loadFile(file string) string {

	if file == "" {
		return ""
	}

	f, err := os.Open(file)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)

	if err != nil {
		log.Fatal(err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
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
