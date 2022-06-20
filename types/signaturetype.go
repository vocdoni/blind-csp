package types

const (
	// SignatureTypeBlind is a secp256k1 blind signature
	SignatureTypeBlind = "blind"
	// SignatureTypeEthereum is the standard secp256k1 signature used in Ethereum
	SignatureTypeEthereum = "ecdsa"
	// SignatureTypeSharedKey identifier the shared key (common for all users on the same processId)
	SignatureTypeSharedKey = "sharedkey"
)

// AllSignatures is a helper list that includes all available CSP signature schemes.
var AllSignatures = []string{SignatureTypeBlind, SignatureTypeEthereum, SignatureTypeSharedKey}
