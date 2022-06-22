package smshandler

import (
	"sync/atomic"

	"github.com/nyaruka/phonenumbers"
)

func SendChallengeTwilio(phone *phonenumbers.PhoneNumber, challenge int) error {
	return nil
}

var ChallengeSolutionMock int32

func SendChallengeMock(phone *phonenumbers.PhoneNumber, challenge int) error {
	atomic.StoreInt32(&ChallengeSolutionMock, int32(challenge))
	return nil
}
