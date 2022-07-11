package smshandler

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/blind-csp/types"
)

func TestSmsHandler(t *testing.T) {
	dir := t.TempDir()
	csvFile := filepath.Join(dir, "import.csv")
	err := os.WriteFile(csvFile, []byte(CSVFILE), 0644)
	qt.Check(t, err, qt.IsNil)
	err = os.Setenv("CSP_IMPORT_FILE", csvFile)
	qt.Check(t, err, qt.IsNil)

	sh := SmsHandler{SendChallenge: sendChallengeMock}
	err = sh.Init(dir, "2", "1") // MaxAttempts:2 CoolDownSeconds:1
	qt.Check(t, err, qt.IsNil)
	sh.SmsThrottle = time.Nanosecond * 1

	msg := types.Message{}
	msg.AuthData = []string{"6c0b6e1020b6354c714fc65aa198eb95e663f038e32026671c58677e0e0f8eac"}
	electionID := types.HexBytes{}
	err = electionID.FromString("c3095ff57150285cccf880e712e353a16251de6670f7aa1b069e6416cb641f5a")
	qt.Check(t, err, qt.IsNil)

	// first attempt (should work)
	resp := sh.Auth(nil, &msg, electionID, "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	// second attempt (should fail because of cooldown time)
	resp = sh.Auth(nil, &msg, electionID, "blind", 0)
	qt.Check(t, resp.Success, qt.IsFalse)

	// second attempt (should work)
	time.Sleep(time.Second * 1)
	resp = sh.Auth(nil, &msg, electionID, "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	// third attempt (should fail)
	resp = sh.Auth(nil, &msg, electionID, "blind", 0)
	qt.Check(t, resp.Success, qt.IsFalse)

	// Try second user
	msg.AuthData = []string{"bf5b6a9c69a5abee870b3667e92c589ef9c13458be0fc0493b2ba5a9658c690b"}
	electionID = types.HexBytes{}
	err = electionID.FromString("7ad9ef89d38a0e55cd8eb6b5f532d34c9ea8d4fe630e0d29247aa94e2e854402")
	qt.Check(t, err, qt.IsNil)

	// first attempt with wrong solution (should fail)
	resp = sh.Auth(nil, &msg, electionID, "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	msg.AuthToken = resp.AuthToken
	msg.AuthData = []string{"1234"}
	resp = sh.Auth(nil, &msg, electionID, "blind", 1)
	qt.Check(t, resp.Success, qt.IsFalse)

	// second attempt with right solution (should work)
	time.Sleep(time.Second * 1)
	msg.AuthData = []string{"bf5b6a9c69a5abee870b3667e92c589ef9c13458be0fc0493b2ba5a9658c690b"}
	resp = sh.Auth(nil, &msg, electionID, "blind", 0)
	qt.Check(t, resp.Success, qt.IsTrue)

	time.Sleep(time.Second) // cooldown time
	msg.AuthToken = resp.AuthToken
	msg.AuthData = []string{fmt.Sprintf("%d", atomic.LoadInt32(&challengeSolutionMock))}
	resp = sh.Auth(nil, &msg, electionID, "blind", 1)
	qt.Check(t, resp.Success, qt.IsTrue, qt.Commentf("%s", resp.Response))

	// Try again, it should fail
	time.Sleep(time.Second) // cooldown time
	msg.AuthToken = resp.AuthToken
	msg.AuthData = []string{fmt.Sprintf("%d", atomic.LoadInt32(&challengeSolutionMock))}
	resp = sh.Auth(nil, &msg, electionID, "blind", 1)
	qt.Check(t, resp.Success, qt.IsFalse)
}

// nolint[:lll]
var CSVFILE = `
6c0b6e1020b6354c714fc65aa198eb95e663f038e32026671c58677e0e0f8eac,+34667722111,John,c3095ff57150285cccf880e712e353a16251de6670f7aa1b069e6416cb641f5a
bf5b6a9c69a5abee870b3667e92c589ef9c13458be0fc0493b2ba5a9658c690b,+34700212841,Mike,7ad9ef89d38a0e55cd8eb6b5f532d34c9ea8d4fe630e0d29247aa94e2e854402
`
