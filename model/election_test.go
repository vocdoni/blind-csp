package model_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/log"
)

func createElection() (*model.Election, model.Election, error) {
	var id types.HexBytes
	if err := id.FromString("c5d2460186f7bb73137b620cffde1b3971a0c9023b480c851b700304000000" + generateID(2)); err != nil {
		log.Error(err)
	}

	newElection := model.Election{
		ID: id,
		Handlers: []model.HandlerConfig{
			{
				Handler: "handler1",
				Service: "service1",
				Mode:    "mode1",
				Data:    []string{"user1", "user2"},
			},
		},
	}

	created, err := electionStore.CreateElection(&newElection)
	return created, newElection, err
}

func TestCreateElection(t *testing.T) {
	created, census, err := createElection()

	var electionID types.HexBytes
	if err := electionID.FromString(census.ID.String()); err != nil {
		log.Error(err)
	}

	qt.Assert(t, created, qt.Not(qt.IsNil))
	qt.Assert(t, created.ID.String(), qt.Equals, electionID.String())
	qt.Assert(t, *created, qt.DeepEquals, census)
	qt.Assert(t, err, qt.IsNil)
}

func TestGetElection(t *testing.T) {
	_, census, _ := createElection()
	var electionID types.HexBytes
	if err := electionID.FromString(census.ID.String()); err != nil {
		log.Error(err)
	}

	election, err := electionStore.Election(electionID)
	qt.Assert(t, election, qt.Not(qt.IsNil))
	qt.Assert(t, election.ID.String(), qt.Equals, electionID.String())
	qt.Assert(t, *election, qt.DeepEquals, census)
	qt.Assert(t, err, qt.IsNil)
}

func TestDeleteElection(t *testing.T) {
	_, census, _ := createElection()
	var electionID types.HexBytes
	if err := electionID.FromString(census.ID.String()); err != nil {
		log.Error(err)
	}

	err := electionStore.DeleteElection(electionID)
	qt.Assert(t, err, qt.IsNil)

	_, err = electionStore.Election(electionID)
	qt.Assert(t, err, qt.ErrorMatches, model.ErrElectionUnknown.Error())
}

func TestListElection(t *testing.T) {
	_, _, _ = createElection()
	_, _, _ = createElection()

	elections, err := electionStore.ListElection()
	qt.Assert(t, err, qt.IsNil)
	greaterOrEqual := len(*elections) >= 2
	qt.Assert(t, greaterOrEqual, qt.IsTrue)
}
