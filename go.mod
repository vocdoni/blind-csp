module github.com/vocdoni/blind-csp

go 1.15

replace github.com/strikesecurity/strikememongo v0.2.4 => github.com/altergui/strikememongo v0.2.4

require (
	github.com/arnaucube/go-blindsecp256k1 v0.0.0-20220421060538-07077d895da5
	github.com/enriquebris/goconcurrentqueue v0.6.3
	github.com/ethereum/go-ethereum v1.10.13
	github.com/frankban/quicktest v1.14.0
	github.com/google/uuid v1.3.0
	github.com/messagebird/go-rest-api/v7 v7.1.0
	github.com/nyaruka/phonenumbers v1.0.75
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.10.1
	github.com/strikesecurity/strikememongo v0.2.4 // direct
	github.com/tendermint/tendermint v0.34.15 // indirect
	github.com/twilio/twilio-go v0.26.0
	go.mongodb.org/mongo-driver v1.9.1
	go.vocdoni.io/dvote v1.0.4-0.20220210143454-e386915ab3d5
)
