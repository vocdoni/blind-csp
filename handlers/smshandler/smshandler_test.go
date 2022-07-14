package smshandler

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/log"
)

func TestSmsHandler(t *testing.T) {
	log.Init("debug", "stderr")

	dir := t.TempDir()
	challenge := newChallengeMock()
	sh := SmsHandler{SendChallenge: challenge.sendChallenge}
	err := sh.Init(dir, "2", "200", "5") // MaxAttempts:2 CoolDownSeconds:200ms Throttle:5ms
	qt.Check(t, err, qt.IsNil)

	// add the users
	for _, ud := range usersMockData {
		err := sh.stg.AddUser(ud.userID, ud.elections, fmt.Sprintf("%d", ud.phone.GetNationalNumber()), "")
		qt.Check(t, err, qt.IsNil)
	}
	t.Log(sh.stg.String())

	// Try first user (only auth step 0)

	// first attempt (should work)
	msg := types.Message{}
	msg.AuthData = []string{usersMockData[0].userID.String()}
	resp := sh.Auth(nil, &msg, usersMockData[0].elections[0], "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	// attempt (should fail because of cooldown time)
	resp = sh.Auth(nil, &msg, usersMockData[0].elections[0], "blind", 0)
	qt.Check(t, resp.Success, qt.IsFalse)

	// second attempt (should work)
	time.Sleep(time.Millisecond * 200) // cooldown time
	resp = sh.Auth(nil, &msg, usersMockData[0].elections[0], "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	// third attempt (should fail)
	time.Sleep(time.Millisecond * 200) // cooldown time
	resp = sh.Auth(nil, &msg, usersMockData[0].elections[0], "blind", 0)
	qt.Check(t, resp.Success, qt.IsFalse)

	// Try second user with step 1 (solution)
	msg.AuthData = []string{usersMockData[1].userID.String()}

	// first attempt with wrong solution (should fail) index:0
	resp = sh.Auth(nil, &msg, usersMockData[1].elections[0], "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	msg.AuthToken = resp.AuthToken
	msg.AuthData = []string{"1234"}
	resp = sh.Auth(nil, &msg, usersMockData[1].elections[0], "blind", 1)
	qt.Check(t, resp.Success, qt.IsFalse)

	// second attempt with right solution (should work) index:1
	time.Sleep(time.Millisecond * 250) // cooldown time
	msg.AuthData = []string{usersMockData[1].userID.String()}
	resp = sh.Auth(nil, &msg, usersMockData[1].elections[0], "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	time.Sleep(time.Millisecond * 250)
	msg.AuthToken = resp.AuthToken
	solution := challenge.getSolution(usersMockData[1].phone, 1)

	msg.AuthData = []string{fmt.Sprintf("%d", solution)}
	resp = sh.Auth(nil, &msg, usersMockData[1].elections[0], "blind", 1)
	qt.Check(t, resp.Success, qt.IsTrue, qt.Commentf("%s", resp.Response))

	// Try again, it should fail
	time.Sleep(time.Millisecond * 250)
	msg.AuthToken = resp.AuthToken
	msg.AuthData = []string{fmt.Sprintf("%d", solution)}
	resp = sh.Auth(nil, &msg, usersMockData[1].elections[0], "blind", 1)
	qt.Check(t, resp.Success, qt.IsFalse)
}

type usersMock struct {
	userID    types.HexBytes
	elections []types.HexBytes
	phone     *phonenumbers.PhoneNumber
}

var usersMockData = []usersMock{
	{
		userID:    testStrToHex("6c0b6e1020b6354c714fc65aa198eb95e663f038e32026671c58677e0e0f8eac"),
		elections: []types.HexBytes{testStrToHex("c3095ff57150285cccf880e712e353a16251de6670f7aa1b069e6416cb641f5a")},
		phone:     mockPhone(),
	},
	{
		userID:    testStrToHex("bf5b6a9c69a5abee870b3667e92c589ef9c13458be0fc0493b2ba5a9658c690b"),
		elections: []types.HexBytes{testStrToHex("7ad9ef89d38a0e55cd8eb6b5f532d34c9ea8d4fe630e0d29247aa94e2e854402")},
		phone:     mockPhone(),
	},
}

// mockPhone returns a phonenumber between +34722000000 and +34722999999
func mockPhone() *phonenumbers.PhoneNumber {
	mathRandom := rand.New(rand.NewSource(time.Now().UnixNano()))
	n := 722000000 + mathRandom.Intn(999999)
	ph, _ := phonenumbers.Parse(fmt.Sprintf("%d", n), "ES")
	return ph
}

func testStrToHex(payload string) types.HexBytes {
	h := types.HexBytes{}
	if err := h.FromString(payload); err != nil {
		panic(err)
	}
	return h
}
