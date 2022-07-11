package smshandler

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"

	qt "github.com/frankban/quicktest"
	"go.vocdoni.io/dvote/log"
)

func TestSmsQueue(t *testing.T) {
	log.Init("debug", "stderr")
	rand.Seed(time.Now().UnixNano())
	smsQueue := newSmsQueue(
		1*time.Second, // smsCoolDownTime
		sendChallengeOnceIn2,
	)
	go smsQueue.run()
	go smsQueueController(smsQueue.response)
	var userID types.HexBytes = []byte{0xff}
	var electionID types.HexBytes = []byte{0xee}
	for i := 0; i < 10; i++ {
		phone := randomPhone()
		err := smsQueue.add(userID, electionID, phone, 1234)
		qt.Check(t, err, qt.IsNil)
		time.Sleep(time.Second)
	}
}

// smsQueueController was copy-pasted from smshandler.go
func smsQueueController(ch <-chan (smsQueueResponse)) {
	for {
		r := <-ch
		if r.success {
			log.Infof("challenge successfully sent to %s", r.userID)
		} else {
			log.Infof("challenge sending failed for %s", r.userID)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// randomPhone returns a random phonenumber between +34722000000 and +34722999999
func randomPhone() *phonenumbers.PhoneNumber {
	n := 722000000 + rand.Intn(999999)
	ph, _ := phonenumbers.Parse(fmt.Sprintf("%d", n), "ES")
	return ph
}

// sendChallengeOnceIn will randomly return nil (success) with 1/i probability
func sendChallengeOnceIn(i int) error {
	if rand.Intn(i) < 1 {
		return nil
	}
	return fmt.Errorf("mock error while trying to send sms")
}

func sendChallengeOnceIn2(phone *phonenumbers.PhoneNumber, challenge int) error {
	return sendChallengeOnceIn(2)
}
