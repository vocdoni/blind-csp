package smshandler

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"
	"time"

	dtypes "github.com/docker/docker/api/types"
	dcontainer "github.com/docker/docker/api/types/container"
	dclient "github.com/docker/docker/client"
	qt "github.com/frankban/quicktest"
	"github.com/google/uuid"
	"github.com/strikesecurity/strikememongo"
	"github.com/vocdoni/blind-csp/types"
)

const coolDownTime = 50 * time.Millisecond
const maxAttempts = 2

func TestStorageJSON(t *testing.T) {
	js := &JSONstorage{}
	testStorage(t, js)
}

func TestStorageMongoDB(t *testing.T) {
	imageName := "mongo:5.0.9"
	containerName := fmt.Sprintf("gotest_mongo_%08d", rand.Intn(100000000))

	ctx := context.Background()
	cli, err := dclient.NewClientWithOpts(dclient.FromEnv, dclient.WithAPIVersionNegotiation())
	qt.Check(t, err, qt.IsNil)

	out, err := cli.ImagePull(ctx, imageName, dtypes.ImagePullOptions{})
	qt.Check(t, err, qt.IsNil)
	defer func() { _ = out.Close() }()
	_, _ = io.Copy(os.Stdout, out) // drain out until closed, this waits until ImagePull is finished

	resp, err := cli.ContainerCreate(ctx, &dcontainer.Config{
		Image: imageName,
	}, nil, nil, nil, containerName)
	qt.Check(t, err, qt.IsNil)

	// best-effort to cleanup the container in most situations, including panic()
	// but note this is not run in case of SIGKILL or CTRL-C and a running mongo docker is left behind
	defer func() {
		_ = cli.ContainerRemove(ctx, resp.ID, dtypes.ContainerRemoveOptions{
			RemoveVolumes: true,
			Force:         true,
		})
	}()

	err = cli.ContainerStart(ctx, resp.ID, dtypes.ContainerStartOptions{})
	qt.Check(t, err, qt.IsNil)

	ct, err := cli.ContainerInspect(ctx, resp.ID)
	qt.Check(t, err, qt.IsNil)

	err = os.Setenv("CSP_MONGODB_URL", fmt.Sprintf("mongodb://%s", ct.NetworkSettings.IPAddress))
	qt.Check(t, err, qt.IsNil)
	err = os.Setenv("CSP_DATABASE", strikememongo.RandomDatabase())
	qt.Check(t, err, qt.IsNil)

	testStorage(t, &MongoStorage{})
}

func testStorage(t *testing.T, stg Storage) {
	dataDir := t.TempDir()
	err := stg.Init(dataDir, maxAttempts, coolDownTime)
	qt.Assert(t, err, qt.IsNil)
	// Add users
	for user, data := range testStorageUsers {
		t.Logf("adding user %s", user)
		uh, ph := testStorageToHex(t, user, data.elections)
		err := stg.AddUser(uh, ph, data.phone, "")
		qt.Assert(t, err, qt.IsNil)
	}
	t.Logf(stg.String())

	users, err := stg.Users()
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, users.Users, qt.HasLen, 3)
	t.Logf("Users: %s", users.Users)

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
	user, err := stg.User(testStrToHex(t, testStorageUser3))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, user.Elections, qt.HasLen, 2)

	// Test verified
	valid, err = stg.Verified(testStrToHex(t, testStorageUser1), testStrToHex(t, testStorageProcess1))
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
	qt.Assert(t, err, qt.ErrorIs, ErrUserNotBelongsToElection)

	// try wrong solution
	err = stg.VerifyChallenge(testStrToHex(t, testStorageProcess1), &token1, 1234)
	qt.Assert(t, err, qt.ErrorIs, ErrChallengeCodeFailure)

	// try valid solution but should not be allowed (already tried before)
	err = stg.VerifyChallenge(testStrToHex(t, testStorageProcess1), &token1, challenge1)
	qt.Assert(t, err, qt.ErrorIs, ErrInvalidAuthToken)

	// try another attempt
	challenge1 = 1989
	token1 = uuid.New()
	time.Sleep(coolDownTime)
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser1),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)

	// try valid solution, should work
	err = stg.VerifyChallenge(testStrToHex(t, testStorageProcess1), &token1, challenge1)
	qt.Assert(t, err, qt.IsNil)

	// now user is verified, we should not be able to ask for more challenges
	token1 = uuid.New()
	time.Sleep(coolDownTime)
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser1),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.ErrorIs, ErrUserAlreadyVerified)

	// try to do attempts too quickly (not respecting coolDownTime) with user3
	token1 = uuid.New()
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser3),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)
	// now coolDownTime is in effect for testStorageUser3 but not for testStorageUser2
	token1 = uuid.New()
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser3),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.ErrorIs, ErrAttemptCoolDownTime)
	// so, wait and try again
	time.Sleep(coolDownTime)
	token1 = uuid.New()
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser3),
		testStrToHex(t, testStorageProcess1), challenge1, &token1)
	qt.Assert(t, err, qt.IsNil)

	// try to consume all attempts for user2
	err = stg.SetAttempts(testStrToHex(t, testStorageUser2),
		testStrToHex(t, testStorageProcess2), -1)
	qt.Assert(t, err, qt.IsNil)

	time.Sleep(coolDownTime)
	token1 = uuid.New()
	_, err = stg.NewAttempt(testStrToHex(t, testStorageUser2),
		testStrToHex(t, testStorageProcess2), challenge1, &token1)
	qt.Assert(t, err, qt.ErrorIs, ErrTooManyAttempts)

	// test verified
	valid, err = stg.Verified(testStrToHex(t, testStorageUser1), testStrToHex(t, testStorageProcess1))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsTrue)

	valid, err = stg.Verified(testStrToHex(t, testStorageUser2), testStrToHex(t, testStorageProcess2))
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, valid, qt.IsFalse)

	valid, err = stg.Verified(testStrToHex(t, testStorageUser3), testStrToHex(t, testStorageProcess1))
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
	testStorageUser2         = "316008c51db028fa544dbf68a4c70811728b602fee46a5d0c8dc0f6300a3c474"
	testStoragePhone2        = "677888999"
	testStorageUser3         = "0467aa5a72daf0286ad89c5220f84a7b2133fbd51ab5d3a85a049a645f54f32f"
	testStoragePhone3        = "+1-541-754-3010"
	testStorageUserNonExists = "22fa4de0788c38755239589dfa18a8d7adbe8bb96425c4641389008470fa0377"

	testStorageUsers = map[string]testUserData{
		testStorageUser1: {elections: []string{testStorageProcess1}, phone: testStoragePhone1},
		testStorageUser2: {elections: []string{testStorageProcess2}, phone: testStoragePhone2},
		testStorageUser3: {
			elections: []string{testStorageProcess1, testStorageProcess2},
			phone:     testStoragePhone3,
		},
	}
)

type testUserData struct {
	elections []string
	phone     string
}
