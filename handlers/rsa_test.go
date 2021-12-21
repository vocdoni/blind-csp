package handlers

import (
	"encoding/hex"
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
		{"___66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01", processId, processId},
		{processId, "___66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01", processId},
		{processId, processId, "___66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab01"},
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
	qt.Assert(t, bb, qt.Equals, "88e66cdf1cac93ded9c8d13b7cc74601c7f25bf50d392549e1146eaa8429ab0151bc804fdb2122c0a8b221bf5b3683395151f30ac6e86d014bb38854eff483de")

	cc := hex.EncodeToString(c)
	qt.Assert(t, cc, qt.Equals, signature)
}

func TestSignature(t *testing.T) {
	_, message, signature, err := parseRsaAuthData([]string{
		processId,
		voterId,
		signature,
	})
	qt.Assert(t, err, qt.IsNil)

	pubK, _ := parseRsaPublicKey()
	err = validateRsaSignature(pubK, message, signature)

	qt.Assert(t, err, qt.IsNil)
}
