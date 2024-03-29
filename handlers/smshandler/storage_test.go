package smshandler

import (
	"context"
	"os"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
	"github.com/vocdoni/blind-csp/test"
	"github.com/vocdoni/blind-csp/types"
)

func TestStorageJSON(t *testing.T) {
	js := &JSONstorage{}
	testStorage(t, js)
}

func TestStorageMongoDB(t *testing.T) {
	ctx := context.Background()
	container, err := test.StartMongoContainer(ctx)
	qt.Assert(t, err, qt.IsNil)
	defer func() { _ = container.Terminate(ctx) }()

	mongoURI, err := container.Endpoint(ctx, "mongodb")
	qt.Assert(t, err, qt.IsNil)

	_ = os.Setenv("CSP_MONGODB_URL", mongoURI)
	_ = os.Setenv("CSP_DATABASE", test.RandomDatabaseName())
	_ = os.Setenv("CSP_RESET_DB", "true")

	testStorage(t, &MongoStorage{})

	qt.Assert(t, err, qt.IsNil)
}

func testStorage(t *testing.T, stg Storage) {
	dataDir := t.TempDir()
	err := stg.Init(dataDir, 2, time.Millisecond*50)
	qt.Assert(t, err, qt.IsNil)
	// Add users
	for user, data := range testStorageUsers {
		t.Logf("adding user %s", user)
		uh, ph := testStorageToHex(t, user, data.elections)
		err := stg.AddUser(uh, ph, data.phone, data.extra)
		qt.Assert(t, err, qt.IsNil)
	}
	t.Logf(stg.String())

	users, err := stg.Users()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, users.Users, qt.HasLen, 3)
	t.Logf("Users: %s", users.Users)

	// Check user 1 with process 1 (should be valid)
	valid, err := stg.BelongsToElection(
		testStrToHex(testStorageUser1),
		testStrToHex(testStorageProcess1),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	// Check user 1 with process 2 (should be invalid)
	valid, err = stg.BelongsToElection(
		testStrToHex(testStorageUser1),
		testStrToHex(testStorageProcess2),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsFalse)

	// Check user 3 with process 1 (should be valid)
	valid, err = stg.BelongsToElection(
		testStrToHex(testStorageUser3),
		testStrToHex(testStorageProcess1),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	// Check user 3 with process 2 (should be valid)
	valid, err = stg.BelongsToElection(
		testStrToHex(testStorageUser3),
		testStrToHex(testStorageProcess2),
	)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	// Test exists
	valid = stg.Exists(testStrToHex(testStorageUser1))
	qt.Assert(t, valid, qt.IsTrue)
	valid = stg.Exists(testStrToHex(testStorageUserNonExists))
	qt.Assert(t, valid, qt.IsFalse)

	// Test get elections
	user, err := stg.User(testStrToHex(testStorageUser3))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, user.Elections, qt.HasLen, 2)

	// Test verified
	valid, err = stg.Verified(testStrToHex(testStorageUser1), testStrToHex(testStorageProcess1))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsFalse)

	// Test attempts
	token1 := uuid.New()
	challenge1 := 1987
	phoneN, err := stg.NewAttempt(testStrToHex(testStorageUser1),
		testStrToHex(testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, int(*phoneN.CountryCode), qt.Equals, 34)

	// try wrong process
	err = stg.VerifyChallenge(testStrToHex(testStorageProcess2), &token1, challenge1)
	qt.Assert(t, err, qt.ErrorIs, ErrUserNotBelongsToElection)

	// try wrong solution
	err = stg.VerifyChallenge(testStrToHex(testStorageProcess1), &token1, 1234)
	qt.Assert(t, err, qt.ErrorIs, ErrChallengeCodeFailure)

	// try valid solution but should not be allowed (already tried before)
	err = stg.VerifyChallenge(testStrToHex(testStorageProcess1), &token1, challenge1)
	qt.Assert(t, err, qt.ErrorIs, ErrInvalidAuthToken)

	// try another attempt
	challenge1 = 1989
	token1 = uuid.New()
	time.Sleep(time.Millisecond * 50) // cooldown time
	_, err = stg.NewAttempt(testStrToHex(testStorageUser1),
		testStrToHex(testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)

	// try valid solution, should work
	err = stg.VerifyChallenge(testStrToHex(testStorageProcess1), &token1, challenge1)
	qt.Assert(t, err, qt.IsNil)

	// now user is verified, we should not be able to ask for more challenges
	token1 = uuid.New()
	time.Sleep(time.Millisecond * 50) // cooldown time
	_, err = stg.NewAttempt(testStrToHex(testStorageUser1),
		testStrToHex(testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.ErrorIs, ErrUserAlreadyVerified)

	// try to consume all attempts for user2
	err = stg.SetAttempts(testStrToHex(testStorageUser2),
		testStrToHex(testStorageProcess2), -1)
	qt.Assert(t, err, qt.IsNil)

	err = stg.SetAttempts(testStrToHex(testStorageUser2),
		testStrToHex(testStorageProcess2), -1)
	qt.Assert(t, err, qt.IsNil)

	token1 = uuid.New()
	_, err = stg.NewAttempt(testStrToHex(testStorageUser2),
		testStrToHex(testStorageProcess2), challenge1, &token1)
	qt.Assert(t, err, qt.ErrorIs, ErrTooManyAttempts)

	// test verified
	valid, err = stg.Verified(testStrToHex(testStorageUser1), testStrToHex(testStorageProcess1))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	valid, err = stg.Verified(testStrToHex(testStorageUser2), testStrToHex(testStorageProcess2))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsFalse)

	t.Logf(stg.String())

	// test search term
	users, err = stg.Search("Smith")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, users.Users, qt.HasLen, 2)
	t.Logf("%s (%d)", users.Users, len(users.Users))
	users, err = stg.Search("Rocky")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, users.Users, qt.HasLen, 0)
	users, err = stg.Search("1940")
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, users.Users, qt.HasLen, 1)
}

func testStorageToHex(t *testing.T, user string, pids []string) (types.HexBytes, []types.HexBytes) {
	uh := types.HexBytes{}
	err := uh.FromString(user)
	qt.Assert(t, err, qt.IsNil)
	ph := []types.HexBytes{}
	for _, p := range pids {
		ph1 := types.HexBytes{}
		if err := ph1.FromString(p); err != nil {
			t.Fatal(err)
		}
		ph = append(ph, ph1)
	}
	return uh, ph
}

var (
	testStorageProcess1      = "8e8353d179a60dc8e12f7c68c2b2dfebc7c34d3f01c49122a9ad4fe632c15216"
	testStorageProcess2      = "e1fed0c1bf0bf797cedfa30e1d92ecf7a9047b53043ea8a242388c276855ccaf"
	testStorageUser1         = "d763cda19aa52c2ff6e13a02989413e47abbee356bf0a8a21a73fc9af48d6ed2"
	testStoragePhone1        = "+34655111222"
	testStorageExtra1        = "John Smith 1977"
	testStorageUser2         = "316008c51db028fa544dbf68a4c70811728b602fee46a5d0c8dc0f6300a3c474"
	testStoragePhone2        = "677888999"
	testStorageExtra2        = "John Lewis 1940"
	testStorageUser3         = "0467aa5a72daf0286ad89c5220f84a7b2133fbd51ab5d3a85a049a645f54f32f"
	testStoragePhone3        = "+1-541-754-3010"
	testStorageExtra3        = "Alice Smith 1971"
	testStorageUserNonExists = "22fa4de0788c38755239589dfa18a8d7adbe8bb96425c4641389008470fa0377"

	testStorageUsers = map[string]testUserData{
		testStorageUser1: {
			elections: []string{testStorageProcess1},
			phone:     testStoragePhone1,
			extra:     testStorageExtra1,
		},
		testStorageUser2: {
			elections: []string{testStorageProcess2},
			phone:     testStoragePhone2,
			extra:     testStorageExtra2,
		},
		testStorageUser3: {
			elections: []string{testStorageProcess1, testStorageProcess2},
			phone:     testStoragePhone3,
			extra:     testStorageExtra3,
		},
	}
)

type testUserData struct {
	elections []string
	phone     string
	extra     string
}
