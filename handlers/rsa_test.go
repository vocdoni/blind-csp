package handlers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	qt "github.com/frankban/quicktest"
)

const processId = "88e66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01"
const voterId = "51bc804fdb2122c0a8b221bf5b3683395151f30ac6e86d014bb38854eff483de"
const signature = "39143730467aefbfbdefbfbdefbfbdefbfbd77efbfbdefbfbdefbfbdefbfbd54757eefbfbd69efbfbd5709efbfbd1e65efbfbd71efbfbdefbfbd55efbfbd1e0eefbfbdefbfbdefbfbd603941efbfbd686cefbfbdefbfbd49470cefbfbdefbfbd0befbfbd48efbfbd20efbfbd48344425efbfbdefbfbdefbfbd6c184058efbfbdefbfbdefbfbd45efbfbdefbfbd133eefbfbd1731724a2829dcb26fefbfbdefbfbd1125efbfbdefbfbd77efbfbdefbfbd49efbfbd56efbfbd05efbfbdefbfbdefbfbd77efbfbdefbfbd2e64efbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbdefbfbd3f431fefbfbdefbfbdefbfbd241e42efbfbdefbfbdefbfbd35efbfbd555ec3bbd9bc59efbfbdefbfbdefbfbd4cefbfbdefbfbd58e1889defbfbdefbfbd2b13efbfbdefbfbdefbfbdefbfbd4b45181d78efbfbdefbfbddbabefbfbd7e18efbfbd7fefbfbdefbfbd3cefbfbdefbfbd21efbfbd61efbfbd12efbfbd39efbfbd0aefbfbdefbfbd42417b586fefbfbdefbfbd0b2d6322efbfbd3fefbfbd1a0213efbfbd0653efbfbd78efbfbdefbfbd58efbfbd2a69c585efbfbdefbfbd61276aefbfbdefbfbd2defbfbdefbfbd091321efbfbdefbfbdefbfbdefbfbdefbfbd0638efbfbd612341efbfbdefbfbd183eefbfbdefbfbdefbfbdefbfbd281e13"

func TestPublicKey(t *testing.T) {
	pubK, err := parseRsaPublicKey()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, pubK, qt.IsNotNil)
}

func TestAuthDataParserErr(t *testing.T) {
	inputVectors := [][]string{
		{"", "", ""},
		{"", ""},
		{""},
		{"___66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01", voterId, signature},
		{processId, "___66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01", signature},
		{processId, voterId, "___66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01"},
		{"1234", "1234", "1234"},
	}

	for _, input := range inputVectors {
		a, b, c, err := parseRsaAuthData(input)
		qt.Assert(t, a, qt.IsNil)
		qt.Assert(t, b, qt.IsNil)
		qt.Assert(t, c, qt.IsNil)
		qt.Assert(t, err, qt.IsNotNil)
	}
}

func TestAuthDataParser(t *testing.T) {
	a, b, c, err := parseRsaAuthData([]string{
		processId,
		voterId,
		signature,
	})

	qt.Assert(t, a, qt.IsNotNil)
	qt.Assert(t, b, qt.IsNotNil)
	qt.Assert(t, c, qt.IsNotNil)
	qt.Assert(t, err, qt.IsNil)

	aa := hex.EncodeToString(a)
	qt.Assert(t, aa, qt.Equals, voterId)

	bb := hex.EncodeToString(b)
	qt.Assert(t, bb, qt.Equals, processId+voterId)

	cc := hex.EncodeToString(c)
	qt.Assert(t, cc, qt.Equals, signature)
}

func TestSignature1(t *testing.T) {
	_, message, sig, err := parseRsaAuthData([]string{
		processId,
		voterId,
		signature,
	})
	qt.Assert(t, err, qt.IsNil)

	pubK, _ := parseRsaPublicKey()
	err = validateRsaSignature(sig, message, pubK)

	qt.Assert(t, err, qt.IsNil)
}

func TestSignature2(t *testing.T) {
	// Manual inputs verified on cyberchef
	message := []byte("hello")
	sig, _ := hex.DecodeString("6ff990e9522a18c5ec75576ac2c3477ae2f85c3e51ac659b37fd87ea1e35955c5b5a72af46dc80224968001369c5c022ae3ae304bef4e6ba992685881b5290c684cd25cc2c694215abf79609d049260fe2bf01e54be0e7ceecbe5e31be95fc8678877d634f3577bde74d09074348fa6aad90a8449defb12fda3136b8eeb58148")
	pubKstr := `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHBhoIO6WsbQR6Dr+fyzwdUfrqz4
G1s4fKvcQR1NqfvGchXHTZZply7P+1NZnO4UX8z7T9VoMRSoS7lM8jdIeOjoyZuk
0WmNHZXGFeDNhoWtX/IZwy7z/e4qUD+rt1xVU3jjJqkQBSyar1FB+x9tG2qMGPhC
4cKjDWyJtRlopwbtAgMBAAE=
-----END PUBLIC KEY-----`

	// Using the first one available so far
	block, _ := pem.Decode([]byte(pubKstr))

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	qt.Assert(t, err, qt.IsNil)

	pubK := parsedKey.(*rsa.PublicKey)

	err = validateRsaSignature(sig, message, pubK)

	qt.Assert(t, err, qt.IsNil)
}

func TestSignature3(t *testing.T) {
	// Manual inputs verified with openssl
	message, _ := hex.DecodeString("88e66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab0151bc804fdb2122c0a8b221bf5b3683395151f30ac6e86d014bb38854eff483de")
	sig, _ := hex.DecodeString("538cd5175e9b03f01dcb7ec725202a268fbbb60355b570c61938e46a5c6de8820d3a567402e785cdc70251c98c2671d9c02a90cafd8b510e2241f978d3ee4c07dc1b67c7fd2313baf1e50a2655ae6c88aa61a4e31243854f8519abfb7c70c33ba0048a34660a8e93d37449b5ed93ef61291ff797e250409ba53119bc4e731f17")
	pubKstr := `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHBhoIO6WsbQR6Dr+fyzwdUfrqz4
G1s4fKvcQR1NqfvGchXHTZZply7P+1NZnO4UX8z7T9VoMRSoS7lM8jdIeOjoyZuk
0WmNHZXGFeDNhoWtX/IZwy7z/e4qUD+rt1xVU3jjJqkQBSyar1FB+x9tG2qMGPhC
4cKjDWyJtRlopwbtAgMBAAE=
-----END PUBLIC KEY-----`

	// Using the first one available so far
	block, _ := pem.Decode([]byte(pubKstr))

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	qt.Assert(t, err, qt.IsNil)

	pubK := parsedKey.(*rsa.PublicKey)

	err = validateRsaSignature(sig, message, pubK)

	qt.Assert(t, err, qt.IsNil)
}
