package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.vocdoni.io/dvote/log"
)

// Message is the JSON API body message used by the CSP and the client
type Message struct {
	Error     string       `json:"error,omitempty"`
	TokenR    HexBytes     `json:"token,omitempty"`
	AuthToken *uuid.UUID   `json:"authToken,omitempty"`
	Payload   HexBytes     `json:"payload,omitempty"`
	Signature HexBytes     `json:"signature,omitempty"`
	SharedKey HexBytes     `json:"sharedkey,omitempty"`
	Title     string       `json:"title,omitempty"`     // reserved for the info handler
	AuthType  string       `json:"authType,omitempty"`  // reserved for the info handler
	AuthSteps []*AuthField `json:"authSteps,omitempty"` // reserved for the info handler
	AuthData  []string     `json:"authData,omitempty"`  // reserved for the auth handler
	Response  []string     `json:"response,omitempty"`  // reserved for the handlers
	Elections []*HexBytes  `json:"elections,omitempty"` // reserved for the indexer handler
}

type AuthField struct {
	Title string `json:"title"`
	Type  string `json:"type"`
}

func (m *Message) Marshal() []byte {
	r, err := json.Marshal(m)
	if err != nil {
		log.Warnf("error marshaling message: %v", err)
	}
	return r
}

func (m *Message) Unmarshal(data []byte) error {
	return json.Unmarshal(data, m)
}

// HexBytes is a []byte which encodes as hexadecimal in json, as opposed to the
// base64 default.
type HexBytes []byte

func (b HexBytes) MarshalBinary() (data []byte, err error) {
	enc := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(enc[0:], b)
	return enc, nil
}

func (b *HexBytes) UnmarshalBinary(data []byte) error {
	// Strip a leading "0x" prefix, for backwards compatibility.
	if len(data) >= 2 && data[0] == '0' && (data[1] == 'x' || data[1] == 'X') {
		data = data[2:]
	}
	decLen := hex.DecodedLen(len(data))
	if cap(*b) < decLen {
		*b = make([]byte, decLen)
	}
	if _, err := hex.Decode(*b, data); err != nil {
		return err
	}
	return nil
}

func (b HexBytes) MarshalJSON() ([]byte, error) {
	enc := make([]byte, hex.EncodedLen(len(b))+2)
	enc[0] = '"'
	hex.Encode(enc[1:], b)
	enc[len(enc)-1] = '"'
	return enc, nil
}

func (b *HexBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("invalid JSON string: %q", data)
	}
	data = data[1 : len(data)-1]

	// Strip a leading "0x" prefix, for backwards compatibility.
	if len(data) >= 2 && data[0] == '0' && (data[1] == 'x' || data[1] == 'X') {
		data = data[2:]
	}

	decLen := hex.DecodedLen(len(data))
	if cap(*b) < decLen {
		*b = make([]byte, decLen)
	}
	if _, err := hex.Decode(*b, data); err != nil {
		return err
	}
	return nil
}
