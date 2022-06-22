package smshandler

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
	"github.com/vocdoni/blind-csp/types"
)

func TestStorage(t *testing.T) {
	js := &JSONstorage{}
	testStorage(t, js)
}

func testStorage(t *testing.T, stg Storage) {
	dataDir := t.TempDir()
	err := stg.Init(dataDir, 2)
	qt.Assert(t, err, qt.IsNil)
	// Add users
	for user, data := range testStorageUsers {
		t.Logf("adding user %s", user)
		uh, ph := testStorageToHex(t, user, data.elections)
		err := stg.AddUser(uh, ph, data.phone, "")
		qt.Assert(t, err, qt.IsNil)
	}

	t.Logf(stg.String())
	// Check user 1 with process 1 (should be valid)
	valid, err := stg.BelongsToElection(
		testStrToHex(t, testStorageUser1),
		testStrToHex(t, testStorageProcess1),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	// Check user 1 with process 2 (should be invalid)
	valid, err = stg.BelongsToElection(
		testStrToHex(t, testStorageUser1),
		testStrToHex(t, testStorageProcess2),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsFalse)

	// Check user 3 with process 1 (should be valid)
	valid, err = stg.BelongsToElection(
		testStrToHex(t, testStorageUser3),
		testStrToHex(t, testStorageProcess1),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	// Check user 3 with process 2 (should be valid)
	valid, err = stg.BelongsToElection(
		testStrToHex(t, testStorageUser3),
		testStrToHex(t, testStorageProcess2),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	// Test exists
	valid = stg.Exists(testStrToHex(t, testStorageUser1))
	qt.Assert(t, valid, qt.IsTrue)
	valid = stg.Exists(testStrToHex(t, testStorageUserNonExists))
	qt.Assert(t, valid, qt.IsFalse)

	// Test get elections
	elections, err := stg.GetElections(testStrToHex(t, testStorageUser3))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(elections), qt.Equals, 2)

	// Test verified
	valid, err = stg.IsVerified(testStrToHex(t, testStorageUser1), testStrToHex(t, testStorageProcess1))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsFalse)

	// Test attempts
	token1 := uuid.New()
	challenge1 := 1987
	phoneN, err := stg.NewAttempt(testStrToHex(t, testStorageUser1),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, int(*phoneN.CountryCode), qt.Equals, 34)

	// try wrong process
	err = stg.VerifyChallenge(testStrToHex(t, testStorageProcess2), &token1, challenge1)
	qt.Assert(t, err, qt.IsNotNil)

	// try wrong solution
	err = stg.VerifyChallenge(testStrToHex(t, testStorageProcess1), &token1, 1234)
	qt.Assert(t, err, qt.IsNotNil)

	// try valid solution but should not be allowed (already tried before)
	err = stg.VerifyChallenge(testStrToHex(t, testStorageProcess1), &token1, challenge1)
	qt.Assert(t, err, qt.IsNotNil)

	// try another attempt
	challenge1 = 1989
	token1 = uuid.New()
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser1),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)

	// try valid solution, should work
	err = stg.VerifyChallenge(testStrToHex(t, testStorageProcess1), &token1, challenge1)
	qt.Assert(t, err, qt.IsNil)

	// now user is verified, we should not be able to ask for more challenges
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser1),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNotNil)

	// try to consume all attempts fro user2
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser2),
		testStrToHex(t, testStorageProcess2), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser2),
		testStrToHex(t, testStorageProcess2), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser2),
		testStrToHex(t, testStorageProcess2), challenge1, &token1)
	qt.Assert(t, err, qt.IsNotNil)

	// Test verified
	valid, err = stg.IsVerified(testStrToHex(t, testStorageUser1), testStrToHex(t, testStorageProcess1))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	valid, err = stg.IsVerified(testStrToHex(t, testStorageUser2), testStrToHex(t, testStorageProcess2))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsFalse)

	t.Logf(stg.String())
}

func testStrToHex(t *testing.T, payload string) types.HexBytes {
	h := types.HexBytes{}
	err := h.FromString(payload)
	qt.Assert(t, err, qt.IsNil)
	return h
}

func testStorageToHex(t *testing.T, user string, pids []string) (types.HexBytes, []types.HexBytes) {
	uh := types.HexBytes{}
	err := uh.FromString(user)
	qt.Assert(t, err, qt.IsNil)
	ph := []types.HexBytes{}
	for _, p := range pids {
		ph1 := types.HexBytes{}
		ph1.FromString(p)
		ph = append(ph, ph1)
	}
	return uh, ph
}

var testStorageProcess1 = "8e8353d179a60dc8e12f7c68c2b2dfebc7c34d3f01c49122a9ad4fe632c15216"
var testStorageProcess2 = "e1fed0c1bf0bf797cedfa30e1d92ecf7a9047b53043ea8a242388c276855ccaf"
var testStorageUser1 = "d763cda19aa52c2ff6e13a02989413e47abbee356bf0a8a21a73fc9af48d6ed2"
var testStoragePhone1 = "+34655111222"
var testStorageUser2 = "316008c51db028fa544dbf68a4c70811728b602fee46a5d0c8dc0f6300a3c474"
var testStoragePhone2 = "677888999"
var testStorageUser3 = "0467aa5a72daf0286ad89c5220f84a7b2133fbd51ab5d3a85a049a645f54f32f"
var testStoragePhone3 = "+1-541-754-3010"
var testStorageUserNonExists = "22fa4de0788c38755239589dfa18a8d7adbe8bb96425c4641389008470fa0377"

var testStorageUsers = map[string]testUserData{
	testStorageUser1: {elections: []string{testStorageProcess1}, phone: testStoragePhone1},
	testStorageUser2: {elections: []string{testStorageProcess2}, phone: testStoragePhone2},
	testStorageUser3: {elections: []string{testStorageProcess1, testStorageProcess2}, phone: testStoragePhone3},
}

type testUserData struct {
	elections []string
	phone     string
}
