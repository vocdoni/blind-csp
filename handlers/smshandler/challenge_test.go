package smshandler

import (
	"fmt"
	"sync"

	"github.com/nyaruka/phonenumbers"
	"go.vocdoni.io/dvote/log"
)

type challengeMock struct {
	lock      sync.RWMutex
	solutions map[string]int
	indexes   map[string]int
}

func newChallengeMock() *challengeMock {
	return &challengeMock{
		solutions: make(map[string]int),
		indexes:   make(map[string]int),
	}
}

func (cm *challengeMock) sendChallenge(phone *phonenumbers.PhoneNumber, challenge int) error {
	cm.lock.Lock()
	defer cm.lock.Unlock()
	p := fmt.Sprintf("%d", phone.GetNationalNumber())
	index, ok := cm.indexes[p]
	if !ok {
		index = 0
	} else {
		index++
	}
	cm.solutions[challengeSolutionKey(phone, index)] = challenge
	cm.indexes[p] = index
	log.Debugf("challenge mock added %d/%d/%d", index, phone.GetNationalNumber(), challenge)
	return nil
}

func (cm *challengeMock) getSolution(phone *phonenumbers.PhoneNumber, index int) int {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	solution, ok := cm.solutions[challengeSolutionKey(phone, index)]
	if !ok {
		panic("no challenge solution for phone with index")
	}
	return solution
}

func challengeSolutionKey(phone *phonenumbers.PhoneNumber, index int) string {
	return fmt.Sprintf("%d_%d", phone.GetNationalNumber(), index)
}
