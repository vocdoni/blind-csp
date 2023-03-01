package admin_test

import (
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/blind-csp/admin"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/crypto/ethereum"
)

func TestValidateAdminToken(t *testing.T) {
	electionIdString := "c5d2460186f7bb73137b620cffde1b3971a0c9023b480c851b70020400000000"
	var electionId types.HexBytes
	err := electionId.FromString(electionIdString)
	qt.Assert(t, err, qt.IsNil)

	adminToken, err := admin.GenerateAdminToken(electionId)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, adminToken, qt.Not(qt.IsNil))

	valid, err := admin.ValidateAdminToken(electionId, adminToken)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)
}

func TestVerifySignatureForElection(t *testing.T) {
	// Generate a new ethereum key pair
	s := ethereum.NewSignKeys()
	if err := s.Generate(); err != nil {
		t.Fatal(err)
	}
	addr := s.AddressString()

	// Generate a fake electionId
	electionIdString := "c5d2460186f7020400000000"
	electionIdString = electionIdString[:12] + strings.TrimPrefix(addr, "0x") + electionIdString[12:]
	var electionId types.HexBytes
	err := electionId.FromString(electionIdString)
	qt.Assert(t, err, qt.IsNil)

	// Sign the message
	messageText := "hello"
	message := []byte(messageText)
	msgSign, err := s.SignEthereum(message)
	qt.Assert(t, err, qt.IsNil)

	valid, err := admin.VerifySignatureForElection(electionId, msgSign, message)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)
}
