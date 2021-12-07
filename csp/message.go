package csp

import (
	"encoding/json"

	"go.vocdoni.io/dvote/log"
	"go.vocdoni.io/dvote/types"
)

type Message struct {
	Error     string         `json:"error,omitempty"`
	Token     types.HexBytes `json:"tokenR,omitempty"`
	Payload   types.HexBytes `json:"payload,omitempty"`
	Signature types.HexBytes `json:"signature,omitempty"`
	SharedKey types.HexBytes `json:"sharedkey,omitempty"`
	AuthData  []string       `json:"authData,omitempty"` // reserved for the auth handler
	Response  string         `json:"response,omitempty"` // reserved for the auth handler
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
