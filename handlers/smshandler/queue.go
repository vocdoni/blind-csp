package smshandler

import (
	"fmt"
	"time"

	"github.com/enriquebris/goconcurrentqueue"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/log"
)

type challengeData struct {
	userID     types.HexBytes
	electionID types.HexBytes
	phone      *phonenumbers.PhoneNumber
	challenge  int
	startTime  time.Time
	attempts   int
}

func (c challengeData) String() string {
	return fmt.Sprintf("%d/%d", c.phone.GetNationalNumber(), c.challenge)
}

type smsQueue struct {
	queue         *goconcurrentqueue.FIFO
	ttl           time.Duration
	throttle      time.Duration
	sendChallenge SendChallengeFunc
	response      chan (smsQueueResponse)
}

type smsQueueResponse struct {
	userID     types.HexBytes
	electionID types.HexBytes
	success    bool
}

func newSmsQueue(ttl, throttle time.Duration, schFnc SendChallengeFunc) *smsQueue {
	return &smsQueue{
		queue:         goconcurrentqueue.NewFIFO(),
		response:      make(chan smsQueueResponse, 1),
		sendChallenge: schFnc,
		ttl:           ttl,
		throttle:      throttle,
	}
}

func (sq *smsQueue) add(userID, electionID types.HexBytes, phone *phonenumbers.PhoneNumber, challenge int) error {
	log.Debugf("%d/%d: enqueued new sms with challenge", phone.GetNationalNumber(), challenge)
	return sq.queue.Enqueue(
		challengeData{
			userID:     userID,
			electionID: electionID,
			phone:      phone,
			challenge:  challenge,
			startTime:  time.Now(),
			attempts:   0,
		},
	)
}

func (sq *smsQueue) run() {
	for {
		time.Sleep(sq.throttle)
		c, err := sq.queue.DequeueOrWaitForNextElement()
		if err != nil {
			log.Warn(err)
			continue
		}
		challenge := c.(challengeData)
		if err := sq.sendChallenge(challenge.phone, challenge.challenge); err != nil {
			// Fail
			log.Warnf("%s: failed to send sms: %v", challenge, err)
			if err := sq.reenqueue(challenge); err != nil {
				log.Warnf("%s: removed from sms queue: %v", challenge, err)
				// Send a signal (channel) to let the caller know we are removing this element
				sq.response <- smsQueueResponse{
					userID:     challenge.userID,
					electionID: challenge.electionID,
					success:    false,
				}
			}
			continue
		}
		// Success
		log.Debugf("%s: sms with challenge successfully sent", challenge)
		// Send a signal (channel) to let the caller know we succeed
		sq.response <- smsQueueResponse{
			userID:     challenge.userID,
			electionID: challenge.electionID,
			success:    true,
		}
	}
}

func (sq *smsQueue) reenqueue(challenge challengeData) error {
	// check if we have to enqueue it again or not
	if challenge.attempts >= queueSMSmaxAttempts || time.Now().After(challenge.startTime.Add(sq.ttl)) {
		return fmt.Errorf("TTL or max attempts reached")
	}
	// enqueue it again
	challenge.attempts++
	if err := sq.queue.Enqueue(challenge); err != nil {
		return fmt.Errorf("cannot enqueue sms: %w", err)
	}
	log.Infof("%s: re-enqueued sms, attempt #%d", challenge, challenge.attempts)
	return nil
}
