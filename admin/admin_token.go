package admin

import (
	"bytes"
	"os"
	"time"

	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/vochain/processid"
)

// GenerateAdminToken generates a new admin token for an election working for the current month
// Token is generated using Keccak256 with a secret key so that ensures that the token
// cannot be easily guessed or tampered with without knowledge of the key.
// Token will be valid for the "current" month (UTC) and the election ID.
func GenerateAdminToken(electionId types.HexBytes) (string, error) {
	secretKey := os.Getenv("CSP_ADMIN_TOKEN_SECRET")

	currentTime := time.Now()
	dateString := currentTime.Format("200601")
	token := ethereum.HashRaw(append([]byte(secretKey), append(electionId, []byte(dateString)...)...))

	return string(token), nil
}

// ValidateAdminToken validates an admin token for an election
func ValidateAdminToken(electionId types.HexBytes, adminToken string) (bool, error) {
	generatedToken, err := GenerateAdminToken(electionId)
	if err != nil {
		return false, err
	}

	return adminToken == generatedToken, nil
}

// VerifySignatureForElection verifies that the signature is from the election creator
func VerifySignatureForElection(electionId types.HexBytes, signature types.HexBytes, data types.HexBytes) (bool, error) {
	address, err := ethereum.AddrFromSignature(data, signature)
	if err != nil {
		return false, err
	}

	// Verify the signer address is from the election creator
	p := processid.ProcessID{}
	if err := p.Unmarshal(electionId); err != nil {
		return false, err
	}

	return bytes.Equal(p.Addr().Bytes(), address.Bytes()), nil
}
