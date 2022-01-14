package rsahandler

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	qt "github.com/frankban/quicktest"
)

const (
	processId = "11898e5652ccadf0d2a84a1f462d9f29a123bdb21315e92c59c56b0bb1b7d422"
	voterId   = "51bc804fdb2122c0a8b221bf5b3683395151f30ac6e86d014bb38854eff483de"
	signature = "9076e34e9e0cf2d4071829985dc525da186686af6084ec12105083d42601099a" +
		"b2cf44f4eeb3a1897d9fbf4254a6fe94b44e9dd267adfc7c3b2fee32af88caef" +
		"0630ca5852043d4914d3b66aaaddab6b381338d058ba727a2e819e9c09318483" +
		"088d11d8fa3ce5d6e0c333add6866926b7fbcdc1b1c9754c22db85b896bb5c21" +
		"5fd8461ec34204a3524c655548c0b46a7a7178dbae8c6b8c84570459ed439e25" +
		"ecfcf2fe22f9237e8f9f90d55e65a179e5f5a6749b0874182a37015e08bd2376" +
		"35ca586231370b46e53dc0d1730f8fa9a08bf428ab9b8a083d3035c86727b648" +
		"7e5796b994977a3d5e1692ab45dd0068bc71e9446ae897f1fbe3ab9c95081c81"
	rsaPubKey = `-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEApc2hU8zulyJzdQE5IPAv
B2BgveoZmYUmPEjSb4DViBoATK1hlaY8Psp5vj0H0L4tM8AlXRhPQlECibhgccig
xQFcG7CLXiSAn7c4XoR+J2SCgx76Fwl9L3WhQigxyKsmpGIqubseydmwfJi4TBnq
qnX4prsW1PT8GpG35t8Qi8PtkXVGmL7G5pkPXtF0hRzKSfhzsDBbJsl6Jk/Rn5Id
pKHXL22FdbE9fGzIlW2a6Zdd0b0Q3FZBMnWLSwo0OwBtC/qNnDTCzboig9djiFmA
yuj8jVhsy050nI72TAONjGKi+xn4lYfdOV2k6TyvpRHfylHouK2v0/bktSlkFI0y
nwIBAw==
-----END PUBLIC KEY-----`
)

func TestPublicKey(t *testing.T) {
	pubK, err := parseRsaPublicKey(rsaPubKey)
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
		res, err := parseRsaAuthData(input)
		qt.Assert(t, res, qt.IsNil)
		qt.Assert(t, err, qt.IsNotNil)
	}
}

func TestAuthDataParser(t *testing.T) {
	res, err := parseRsaAuthData([]string{
		processId,
		voterId,
		signature,
	})

	qt.Assert(t, res.VoterId, qt.IsNotNil)
	qt.Assert(t, res.Message, qt.IsNotNil)
	qt.Assert(t, res.Signature, qt.IsNotNil)
	qt.Assert(t, err, qt.IsNil)

	aa := hex.EncodeToString(res.VoterId)
	qt.Assert(t, aa, qt.Equals, voterId)

	bb := hex.EncodeToString(res.Message)
	qt.Assert(t, bb, qt.Equals, processId+voterId)

	cc := hex.EncodeToString(res.Signature)
	qt.Assert(t, cc, qt.Equals, signature)
}

func TestSignature1(t *testing.T) {
	// Raw inputs
	res, err := parseRsaAuthData([]string{
		processId,
		voterId,
		signature,
	})
	qt.Assert(t, err, qt.IsNil)

	pubK, _ := parseRsaPublicKey(rsaPubKey)
	err = validateRsaSignature(res.Signature, res.Message, pubK)

	qt.Assert(t, err, qt.IsNil)

	// Digested message
	msg, _ := hex.DecodeString("11898e5652ccadf0d2a84a1f462d9f29a123bdb21315e92c59c56b0bb1b7d42251bc804fdb2122c0a8b221bf5b3683395151f30ac6e86d014bb38854eff483de")
	sig, _ := hex.DecodeString(signature)
	err = validateRsaSignature(sig, msg, pubK)

	qt.Assert(t, err, qt.IsNil)
}

func TestSignature2(t *testing.T) {
	// Manual inputs verified on cyberchef
	message := []byte("hello")
	sig, err := hex.DecodeString(
		"6ff990e9522a18c5ec75576ac2c3477ae2f85c3e51ac659b37fd87ea1e35955c" +
			"5b5a72af46dc80224968001369c5c022ae3ae304bef4e6ba992685881b5290c6" +
			"84cd25cc2c694215abf79609d049260fe2bf01e54be0e7ceecbe5e31be95fc86" +
			"78877d634f3577bde74d09074348fa6aad90a8449defb12fda3136b8eeb58148",
	)
	qt.Assert(t, err, qt.IsNil)
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

	qt.Assert(t,
		validateRsaSignature(sig, message, parsedKey.(*rsa.PublicKey)),
		qt.IsNil,
	)
}

func TestSignature3(t *testing.T) {
	// Manual inputs verified with openssl
	message, _ := hex.DecodeString("88e66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01" +
		"51bc804fdb2122c0a8b221bf5b3683395151f30ac6e86d014bb38854eff483de")
	sig, err := hex.DecodeString("538cd5175e9b03f01dcb7ec725202a268fbbb60355b570c61938e46a5c6de882" +
		"0d3a567402e785cdc70251c98c2671d9c02a90cafd8b510e2241f978d3ee4c07" +
		"dc1b67c7fd2313baf1e50a2655ae6c88aa61a4e31243854f8519abfb7c70c33b" +
		"a0048a34660a8e93d37449b5ed93ef61291ff797e250409ba53119bc4e731f17",
	)
	qt.Assert(t, err, qt.IsNil)
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

	qt.Assert(t,
		validateRsaSignature(sig, message, parsedKey.(*rsa.PublicKey)),
		qt.IsNil,
	)
}
