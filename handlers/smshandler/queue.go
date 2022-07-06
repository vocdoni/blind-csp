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
	tries      int
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
	var sq smsQueue
	sq.queue = goconcurrentqueue.NewFIFO()
	sq.response = make(chan smsQueueResponse, 10)
	sq.sendChallenge = schFnc
	return &sq
}

func (sq *smsQueue) add(userID, electionID types.HexBytes, phone *phonenumbers.PhoneNumber, challenge int) {
	sq.queue.Enqueue(
		challengeData{
			userID:     userID,
			electionID: electionID,
			phone:      phone,
			challenge:  challenge,
			startTime:  time.Now(),
			tries:      0,
		},
	)
	log.Debugf("enqueued new challenge for phone %d", phone.NationalNumber)
}

func (sq *smsQueue) run() {
	for {
		c, err := sq.queue.DequeueOrWaitForNextElement()
		if err != nil {
			log.Warn(err)
			continue
		}
		var challenge challengeData
		challenge = c.(challengeData)
		if err := sq.sendChallenge(challenge.phone, challenge.challenge); err != nil {
			log.Warnf("failed to send challenge: %v", err)

			// check if we have to enqueue it again or not
			if challenge.tries >= queueSMSmaxTries || time.Now().After(challenge.startTime.Add(sq.ttl)) {
				log.Warnf("TTL or max tries reached for %d, removing from queue", *challenge.phone.NationalNumber)
				// Send a signal (channel) to let the caller know we are removing this element
				sq.response <- smsQueueResponse{
					userID:     challenge.userID,
					electionID: challenge.electionID,
					success:    false,
				}
				continue
			}
			// enqueue it again
			challenge.tries++
			if err := sq.queue.Enqueue(challenge); err != nil {
				log.Errorf("cannot enqueue element: %v", err)
				continue
			}
			log.Infof("added %d to queue for another attempt", *challenge.phone.NationalNumber)
			continue
		}
		log.Debug("challenge successfully sent, sending channel signal")
		// Send a signal (channel) to let the caller know we succeed
		sq.response <- smsQueueResponse{
			userID:     challenge.userID,
			electionID: challenge.electionID,
			success:    true,
		}
	}
}
