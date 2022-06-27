package smshandler

import (
	"fmt"
	"os"
	"sync/atomic"

	messagebird "github.com/messagebird/go-rest-api/v7"
	mbsms "github.com/messagebird/go-rest-api/v7/sms"

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
	accountSid := os.Getenv("SMS_PROVIDER_USERNAME")
	authToken := os.Getenv("SMS_PROVIDER_AUTHTOKEN")
	var tw TwilioSMS
	tw.from = os.Getenv("SMS_FROM")
	if tw.from == "" {
		tw.from = "vocdoni"
	}
	tw.body = os.Getenv("SMS_BODY")
	if tw.body == "" {
		tw.body = "Your authentication code is"
	}
	tw.client = twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSid,
		Password: authToken,
	})
	return &tw
}

func (tw *TwilioSMS) SendChallenge(phone *phonenumbers.PhoneNumber, challenge int) error {
	phoneStr := fmt.Sprintf("+%d%d", phone.GetCountryCode(), phone.GetNationalNumber())
	log.Infof("sending challenge to %s", phoneStr)
	params := &openapi.CreateMessageParams{}
	params.SetTo(phoneStr)
	params.SetFrom(tw.from)
	params.SetBody(fmt.Sprintf("%s %d", tw.body, challenge))
	_, err := tw.client.Api.CreateMessage(params)
	return err
}

type MessageBirdSMS struct {
	client *messagebird.Client
	from   string
	body   string
}

func NewMessageBirdSMS() *MessageBirdSMS {
	var sms MessageBirdSMS
	sms.from = os.Getenv("SMS_FROM")
	if sms.from == "" {
		sms.from = "vocdoni"
	}
	sms.body = os.Getenv("SMS_BODY")
	if sms.body == "" {
		sms.body = "Your authentication code is"
	}
	accessKey := os.Getenv("SMS_PROVIDER_AUTHTOKEN")
	sms.client = messagebird.New(accessKey)
	return &sms
}

func (sms *MessageBirdSMS) SendChallenge(phone *phonenumbers.PhoneNumber, challenge int) error {
	phoneStr := fmt.Sprintf("+%d%d", phone.GetCountryCode(), phone.GetNationalNumber())
	body := fmt.Sprintf("%s %d", sms.body, challenge)
	log.Infof("sending challenge to %s", phoneStr)
	_, err := mbsms.Create(sms.client, sms.from, []string{phoneStr}, body, nil)

	return err
}

var ChallengeSolutionMock int32

func SendChallengeMock(phone *phonenumbers.PhoneNumber, challenge int) error {
	atomic.StoreInt32(&ChallengeSolutionMock, int32(challenge))
	return nil
}
