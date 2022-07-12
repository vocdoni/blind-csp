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

const testIterations = 20
const smsThrottleTime = DefaultSMSthrottleTime

func TestSmsQueue(t *testing.T) {
	log.Init("debug", "stderr")
	rand.Seed(time.Now().UnixNano())
	smsQueue := newSmsQueue(
		time.Second, // smsCoolDownTime
		sendChallengeOnceIn10,
	)
	smsQueue.setThrottle(time.Millisecond)
	go smsQueue.run()
	var electionID types.HexBytes = []byte{0xee}
	for i := 0; i < testIterations; i++ {
		err := smsQueue.add(mockUser(i), electionID, mockPhone(i), 1234)
		qt.Check(t, err, qt.IsNil)
		//time.Sleep(time.Second) // wait a bit between each mock sms attempt
	}
	smsQueueController(smsQueue.response)
}

// smsQueueController was copy-pasted from smshandler.go
// but instead of leaving it running as a goroutine, wrap in a loop of known iterations
func smsQueueController(ch <-chan (smsQueueResponse)) {
	for i := 0; i < testIterations; i++ {
		r := <-ch
		if r.success {
			log.Infof("challenge successfully sent to %s", r.userID)
		} else {
			log.Infof("challenge sending failed for %s", r.userID)
		}
	}
}

func mockUser(i int) types.HexBytes {
	var userID types.HexBytes = []byte{0xfe, 0xde, byte(i)}
	return userID
}

// randomPhone returns a random phonenumber between +34722000000 and +34722999999
func randomPhone() *phonenumbers.PhoneNumber {
	return mockPhone(rand.Intn(999999))
}

// mockPhone returns a phonenumber between +34722000000 and +34722999999
func mockPhone(i int) *phonenumbers.PhoneNumber {
	n := 722000000 + i
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

func sendChallengeOnceIn10(phone *phonenumbers.PhoneNumber, challenge int) error {
	return sendChallengeOnceIn(10)
}
