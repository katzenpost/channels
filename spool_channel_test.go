// spool_channel_test.go - spool channel tests
// Copyright (C) 2019  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package channels

import (
	"fmt"
	"testing"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/memspool/client"
	"github.com/katzenpost/memspool/common"
	"github.com/stretchr/testify/assert"
)

type mockRemoteSpool struct {
	count  byte
	spool  map[[common.SpoolIDSize]byte]map[uint32][]byte
	offset map[[common.SpoolIDSize]byte]uint32
}

func (m *mockRemoteSpool) CreateSpool(privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) ([]byte, error) {
	id := [common.SpoolIDSize]byte{}
	id[0] = m.count
	fmt.Printf("create spool %d\n", id)
	m.count++
	m.spool[id] = make(map[uint32][]byte)
	m.offset[id] = 1
	return id[:], nil
}

func (m *mockRemoteSpool) ReadFromSpool(spoolID []byte, messageID uint32, privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) (*common.SpoolResponse, error) {
	id := [common.SpoolIDSize]byte{}
	copy(id[:], spoolID)
	fmt.Printf("read from spool %d\n", id)
	response := common.SpoolResponse{
		SpoolID: id[:],
		Message: m.spool[id][messageID],
		Status:  "OK",
	}
	return &response, nil
}

func (m *mockRemoteSpool) AppendToSpool(spoolID []byte, message []byte, spoolReceiver string, spoolProvider string) error {
	fmt.Printf("Append to spool ID %d\n", spoolID)
	id := [common.SpoolIDSize]byte{}
	copy(id[:], spoolID)
	m.spool[id][m.offset[id]] = message
	m.offset[id]++
	return nil
}

func (m *mockRemoteSpool) PurgeSpool(spoolID []byte, privKey *eddsa.PrivateKey, recipient, provider string) error {
	id := [common.SpoolIDSize]byte{}
	copy(id[:], spoolID)
	m.spool[id] = make(map[uint32][]byte)
	return nil
}

func newMockRemoteSpool() client.SpoolService {
	return &mockRemoteSpool{
		spool:  make(map[[common.SpoolIDSize]byte]map[uint32][]byte),
		offset: make(map[[common.SpoolIDSize]byte]uint32),
		count:  0,
	}
}

func newTestSpoolChannelPair(t *testing.T) (*UnreliableSpoolChannel, *UnreliableSpoolChannel) {
	assert := assert.New(t)

	receiverA := "receiver_A"
	providerA := "provider_A"
	remoteSpool := newMockRemoteSpool()
	chanA, err := NewUnreliableSpoolChannel(receiverA, providerA, remoteSpool)
	assert.NoError(err)

	receiverB := "receiver_B"
	providerB := "provider_B"
	chanB, err := NewUnreliableSpoolChannel(receiverB, providerB, remoteSpool)
	assert.NoError(err)

	chanADescriptor := chanA.GetSpoolWriter()
	assert.NotNil(chanADescriptor)
	err = chanB.WithRemoteWriter(chanADescriptor)
	assert.NoError(err)

	chanBDescriptor := chanB.GetSpoolWriter()
	err = chanA.WithRemoteWriter(chanBDescriptor)
	assert.NoError(err)

	return chanA, chanB
}

func TestSimpleSpoolChannel(t *testing.T) {
	assert := assert.New(t)

	chanA, chanB := newTestSpoolChannelPair(t)

	msg1 := []byte(`Chaum’s 1981 paper 49 Untraceable Electronic Mail, Return Addresses, and
Digital Pseudonyms, [Chaum81], suggests that a crucial privacy goal when
sending an email is to hide who is communicating with whom. The metadata, in
modern political parlance. The author offered mix nets for a solution. 50`)
	err := chanA.Write(msg1)
	assert.NoError(err)

	msg1Read, err := chanB.Read()
	assert.NoError(err)
	assert.Equal(msg1, msg1Read)

	msg2 := []byte(`Chaum would go on to provide the founding ideas for anonymous electronic
cash and electronic voting. His papers would routinely draw on overtly political
motivations. 51 In a recent conversation, Chaum expressed surprise at the extent
to which academics gravitated to a field—cryptography—so connected to issues
of power. 52`)
	err = chanB.Write(msg2)
	assert.NoError(err)

	msg2Read, err := chanA.Read()
	assert.NoError(err)
	assert.Equal(msg2, msg2Read)
}

func TestSimpleSpoolChannelSerialize(t *testing.T) {
	assert := assert.New(t)
	chanA, chanB := newTestSpoolChannelPair(t)

	// firstly, we test that the channel is working with one write and one read
	msg1 := []byte(`Chaum’s 1981 paper 49 Untraceable Electronic Mail, Return Addresses, and
Digital Pseudonyms, [Chaum81], suggests that a crucial privacy goal when
sending an email is to hide who is communicating with whom. The metadata, in
modern political parlance. The author offered mix nets for a solution. 50`)
	err := chanA.Write(msg1)
	assert.NoError(err)

	msg1Read, err := chanB.Read()
	assert.NoError(err)
	assert.Equal(msg1, msg1Read)

	// then we replace chanA with chanC
	chanCSerialized, err := chanA.Save()
	assert.NoError(err)
	assert.True(len(chanCSerialized) > 1)

	chanC, err := LoadUnreliableSpoolChannel(chanCSerialized, chanA.spoolService)
	assert.NoError(err)

	// and then chanB writes to chanC
	msg2 := []byte(`Chaum would go on to provide the founding ideas for anonymous electronic
		cash and electronic voting. His papers would routinely draw on overtly political
		motivations. 51 In a recent conversation, Chaum expressed surprise at the extent
		to which academics gravitated to a field—cryptography—so connected to issues
		of power. 52`)
	err = chanB.Write(msg2)
	assert.NoError(err)

	msg2Read, err := chanC.Read()
	assert.NoError(err)
	assert.Equal(msg2, msg2Read)
}
