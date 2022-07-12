package smshandler

import (
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

type smsQueue struct {
	queue         *goconcurrentqueue.FIFO
	ttl           time.Duration
	sendChallenge SendChallengeFunc
	response      chan (smsQueueResponse)
}

type smsQueueResponse struct {
	userID     types.HexBytes
	electionID types.HexBytes
	success    bool
}

func newSmsQueue(ttl time.Duration, schFnc SendChallengeFunc) *smsQueue {
	return &smsQueue{
		queue:         goconcurrentqueue.NewFIFO(),
		response:      make(chan smsQueueResponse, 1),
		sendChallenge: schFnc,
		ttl:           ttl,
	}
}

func (sq *smsQueue) add(userID, electionID types.HexBytes, phone *phonenumbers.PhoneNumber, challenge int) error {
	log.Debugf("enqueued new sms with challenge for phone %d", phone.GetNationalNumber())
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
		c, err := sq.queue.DequeueOrWaitForNextElement()
		if err != nil {
			log.Warn(err)
			continue
		}
		challenge := c.(challengeData)
		if err := sq.sendChallenge(challenge.phone, challenge.challenge); err != nil {
			log.Warnf("failed to send sms for %d: %v", challenge.phone.GetNationalNumber(), err)

			// check if we have to enqueue it again or not
			if challenge.attempts >= queueSMSmaxAttempts || time.Now().After(challenge.startTime.Add(sq.ttl)) {
				log.Warnf("TTL or max attempts reached for %d, removing from sms queue", challenge.phone.GetNationalNumber())
				// Send a signal (channel) to let the caller know we are removing this element
				sq.response <- smsQueueResponse{
					userID:     challenge.userID,
					electionID: challenge.electionID,
					success:    false,
				}
				continue
			}
			// enqueue it again
			challenge.attempts++
			if err := sq.queue.Enqueue(challenge); err != nil {
				log.Errorf("cannot enqueue sms for %d: %v", challenge.phone.GetNationalNumber(), err)
				continue
			}
			log.Infof("re-enqueued sms for %d, attempt #%d", challenge.phone.GetNationalNumber(), challenge.attempts)
			continue
		}
		log.Debugf("sms with challenge for %d successfully sent, sending channel signal", challenge.phone.GetNationalNumber())
		// Send a signal (channel) to let the caller know we succeed
		sq.response <- smsQueueResponse{
			userID:     challenge.userID,
			electionID: challenge.electionID,
			success:    true,
		}
	}
}
