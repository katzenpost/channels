// noise_channel_test.go - Noise channel tests
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestNoiseChannelPair(t *testing.T) (*UnreliableNoiseChannel, *UnreliableNoiseChannel) {
	assert := assert.New(t)

	receiverA := "receiver_A"
	providerA := "provider_A"
	remoteSpool := newMockRemoteSpool()
	chanA, err := NewUnreliableNoiseChannel(receiverA, providerA, remoteSpool)
	assert.NoError(err)

	receiverB := "receiver_B"
	providerB := "provider_B"
	chanB, err := NewUnreliableNoiseChannel(receiverB, providerB, remoteSpool)
	assert.NoError(err)

	chanADescriptor := chanA.GetRemoteWriter()
	chanB.WithRemoteWriter(chanADescriptor)
	assert.NoError(err)

	chanBDescriptor := chanB.GetRemoteWriter()
	chanA.WithRemoteWriter(chanBDescriptor)
	assert.NoError(err)

	return chanA, chanB
}

func TestSimpleNoiseChannel(t *testing.T) {
	assert := assert.New(t)

	chanA, chanB := newTestNoiseChannelPair(t)

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

func TestSimpleNoiseChannelSerialize(t *testing.T) {
	assert := assert.New(t)
	chanA, chanB := newTestNoiseChannelPair(t)

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

	chanC, err := LoadUnreliableNoiseChannel(chanCSerialized, chanA.spoolService)
	assert.NoError(err)
	chanC.SetSpoolService(chanA.spoolService)

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
