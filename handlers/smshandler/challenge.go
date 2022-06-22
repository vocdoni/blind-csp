package smshandler

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/nyaruka/phonenumbers"
	"github.com/twilio/twilio-go"
	openapi "github.com/twilio/twilio-go/rest/api/v2010"
	"go.vocdoni.io/dvote/log"
)

type TwilioSMS struct {
	client *twilio.RestClient
	from   string
	body   string
}

func NewTwilioSMS() *TwilioSMS {
	accountSid := os.Getenv("TWILIO_SID")
	authToken := os.Getenv("TWILIO_TOKEN")
	var tw TwilioSMS
	tw.from = os.Getenv("TWILIO_FROM")
	if tw.from == "" {
		tw.from = "vocdoni.app"
	}
	tw.body = os.Getenv("TWILIO_BODY")
	if tw.body == "" {
		tw.body = "Your authentication code is"
	}
	tw.client = twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSid,
		Password: authToken,
	})
	return &tw
}

func (tw *TwilioSMS) SendChallengeTwilio(phone *phonenumbers.PhoneNumber, challenge int) error {
	phoneStr := fmt.Sprintf("+%d%d", phone.GetCountryCode(), phone.GetNationalNumber())
	log.Infof("sending challenge to %s", phoneStr)
	params := &openapi.CreateMessageParams{}
	params.SetTo(phoneStr)
	params.SetFrom(tw.from)
	params.SetBody(fmt.Sprintf("%s %d", tw.body, challenge))
	_, err := tw.client.Api.CreateMessage(params)
	return err
}

var ChallengeSolutionMock int32

func SendChallengeMock(phone *phonenumbers.PhoneNumber, challenge int) error {
	atomic.StoreInt32(&ChallengeSolutionMock, int32(challenge))
	return nil
}
