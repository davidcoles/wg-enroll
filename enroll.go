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
	"time"

	"golang.org/x/crypto/curve25519"
)

type DeviceInfo struct {
	MAC       string            `json:"mac,omitempty"`
	WireGuard string            `json:"wireguard,omitempty"`
	Lshw      string            `json:"lshw,omitempty"`      // lshw -json
	Lspci     string            `json:"lspci,omitempty"`     // lspci -vvnn
	SSH       map[string]string `json:"ssh,omitempty"`       // $(cat /etc/ssh/*.pub | sed 's/ /:/g' | cut -d: -f1-2)
	Timestamp int64             `json:"timestamp,omitempty"` // seconds since epoch
}

func (d *DeviceInfo) base64() (string, error) {
	payload, err := json.Marshal(d)

	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func (d *DeviceInfo) marshal() ([]byte, error) { return json.Marshal(d) }

// enrol [-lshw lshw.json] [-lspci lspci.txt] <mac> <configfile> [ssh:key]...
// systemctl enable wg-quick@wg0.service

var gen = flag.Bool("gen", false, "generate signing key public/private pair to stdout")
var lshw = flag.String("lshw", "", "lshw -json")
var lspci = flag.String("lspci", "", "lspci -vvnn")

// token valididty checker: https://justwebtoken.io/verify/

func main() {

	var mac MAC

	flag.Parse()
	args := flag.Args()

	if *gen {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		seed := priv.Seed()
		// use RawURLEncoding as it is more in keeping with JWT
		fmt.Printf("pub: %s priv: %s\n", base64.RawURLEncoding.EncodeToString(pub[:]), base64.RawURLEncoding.EncodeToString(seed[:]))
		return
	}

	if m, err := hex.DecodeString(args[0]); err != nil {
		panic(err)
	} else {
		copy(mac[:], m)
	}

	conf := loadConf(args[1])
	keys := args[2:]

	wgpub, wgpriv, err := wg()

	if err != nil {
		log.Fatalf("Couldn't generate WireGuard keys: %s\n", err)
	}

	pub, priv, err := conf.keys()

	if err != nil {
		log.Fatalf("Couldn't load signing key: %s\n", err)
	}

	log.Println("Signing with", base64.StdEncoding.EncodeToString(pub[:]))

	var device DeviceInfo
	device.MAC = mac.String()
	device.WireGuard = wgpub.encode()
	//device.Lshw = base64.RawURLEncoding.EncodeToString(loadFile(*lshw))
	//device.Lspci = base64.RawURLEncoding.EncodeToString(loadFile(*lspci))
	device.Lshw = base64.StdEncoding.EncodeToString(loadFile(*lshw))   // to work with standard CLI base64 -d
	device.Lspci = base64.StdEncoding.EncodeToString(loadFile(*lspci)) // to work with standard CLI base64 -d
	device.SSH = map[string]string{}
	device.Timestamp = time.Now().Unix() // seconds since epoch

	re := regexp.MustCompile("^([-a-z0-9]+):([-+_=/a-zA-Z0-9]+)$")

	for _, k := range keys {
		m := re.FindStringSubmatch(k)
		if len(m) != 3 {
			log.Fatal("Funny looking SSH key ... ", k)
		}

		device.SSH[m[1]] = m[2]
	}

	payload, err := device.marshal()

	if err != nil {
		log.Fatal("payload marshal", err)
	}

	jwt := tokenise(payload, priv)

	log.Println("Registrar is", conf.Registrar)

	url := conf.Registrar + mac.String()
	resp, err := http.Post(url, "application/jose", bytes.NewReader([]byte(jwt)))

	if err != nil {
		log.Fatalf("POST failed: %s\n", err)
	}

	defer resp.Body.Close()

	reply, err := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("StatusCode: %d - %s\n", resp.StatusCode, string(reply))
	}

	fmt.Println(conf.conf(wgpriv, mac)) // wg0.conf
}

func loadFile(file string) []byte {

	if file == "" {
		return nil
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

	return b
}

func loadConf(file string) (w wgconf) {

	err := json.Unmarshal(loadFile(file), &w)

	if err != nil {
		log.Fatal(err)
	}

	return
}

type Key [32]byte

func (k *Key) encode() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func wg() (pub Key, priv Key, err error) {
	// follow same process as wireguard-tools/src/genkey.c

	if n, err := rand.Read(priv[:]); err != nil {
		return pub, priv, err
	} else if n != 32 {
		return pub, priv, errors.New("Failed to read 32 bytes from random source")
	}

	// clamp private key (yeah, me neither ...️) as per: https://cr.yp.to/ecdh.html
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub_, err := curve25519.X25519(priv[:], curve25519.Basepoint)

	if err != nil {
		return pub, priv, err
	}

	if len(pub_) != 32 {
		return pub, priv, errors.New("Key is not 32 bytes long")
	}

	copy(pub[:], pub_[:])

	return pub, priv, nil
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

func (c *wgconf) keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	seed, err := base64.RawURLEncoding.DecodeString(c.SigningKey) // use RawURLEncoding as it is more in keeping with JWT

	if err != nil {
		return nil, nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv, nil
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
	s = append(s, "MTU = 1400")
	s = append(s, "[Peer]")
	s = append(s, "PublicKey = "+c.PublicKey)
	s = append(s, "Endpoint = "+c.Endpoint)
	s = append(s, "AllowedIPs = "+c.Prefix.Masked().String())
	s = append(s, "PersistentKeepalive = "+pka)
	s = append(s, "")
	return strings.Join(s, "\n")
}

func tokenise(payload []byte, priv ed25519.PrivateKey) string {
	pub := priv.Public().(ed25519.PublicKey)
	pub64 := base64.RawURLEncoding.EncodeToString(pub[:])
	header := []byte(`{"kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"` + pub64 + `"}`)
	header64 := base64.RawURLEncoding.EncodeToString(header)
	payload64 := base64.RawURLEncoding.EncodeToString(payload)
	preamble := header64 + "." + payload64
	signature64 := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(preamble)))
	return preamble + "." + signature64
}
