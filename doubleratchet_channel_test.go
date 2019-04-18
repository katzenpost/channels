// doubleratchet_channel_test.go - Signal Double Ratchet channel tests
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

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/memspool/common"
	"github.com/stretchr/testify/assert"
)

func TestSimpleDoubleRatchet(t *testing.T) {
	assert := assert.New(t)

	chanA, chanB := newTestSpoolChannelPair(t)

	ratchetChanA, err := NewUnreliableDoubleRatchetChannel(chanA)
	assert.NoError(err)
	ratchetChanB, err := NewUnreliableDoubleRatchetChannel(chanB)
	assert.NoError(err)

	kxA, err := ratchetChanA.KeyExchange()
	assert.NoError(err)
	kxB, err := ratchetChanB.KeyExchange()
	assert.NoError(err)

	err = ratchetChanA.ProcessKeyExchange(kxB)
	assert.NoError(err)
	err = ratchetChanB.ProcessKeyExchange(kxA)
	assert.NoError(err)

	msg1 := []byte(`1. Privacy is personal good. It’s about your desire to control personal informa-
tion about you.
2. Security, on the other hand, is a collective good. It’s about living in a safe
and secure world.
3. Privacy and security are inherently in conflict. As you strengthen one, you
weaken the other. We need to find the right balance.
4. Modern communications technology has destroyed the former balance. It’s
been a boon to privacy, and a blow to security. Encryption is especially
threatening. Our laws just haven’t kept up. 104
5. Because of this, bad guys may win. The bad guys are terrorists, murderers,
child pornographers, drug traffickers, and money launderers. 105 The technol-
ogy that we good guys use—the bad guys use it too, to escape detection.
6. At this point, we run the risk of Going Dark. 106 Warrants will be issued,
but, due to encryption, they’ll be meaningless. We’re becoming a country of
unopenable closets. Default encryption may make a good marketing pitch,
but it’s reckless design. It will lead us to a very dark place.`)
	err = ratchetChanA.Write(msg1)
	assert.NoError(err)

	msg1Read, err := ratchetChanB.Read()
	assert.NoError(err)
	assert.Equal(msg1, msg1Read)

	msg2 := []byte(`1. Surveillance is an instrument of power. 110 It is part of an apparatus of
control. Power need not be in-your-face to be effective: subtle, psychological,
nearly invisible methods can actually be more effective.
2. While surveillance is nothing new, technological changes have given govern-
ments and corporations an unprecedented capacity to monitor everyone’s
communication and movement. Surveilling everyone has became cheaper
than figuring out whom to surveil, and the marginal cost is now tiny. 111 The
Internet, once seen by many as a tool for emancipation, is being transformed
into the most dangerous facilitator for totalitarianism ever seen. 112
3. Governmental surveillance is strongly linked to cyberwar. Security vulner-
abilities that enable one enable the other. And, at least in the USA, the
same individuals and agencies handle both jobs. Surveillance is also strongly
linked to conventional warfare. As Gen. Michael Hayden has explained, “we
kill people based on metadata.” 113 Surveillance and assassination by drones
are one technological ecosystem.
4. The law-enforcement narrative is wrong to position privacy as an individual
good when it is, just as much, a social good. It is equally wrong to regard
privacy and security as conflicting values, as privacy enhances security as
often as it rubs against it.
5. Mass surveillance will tend to produce uniform, compliant, and shallow
people. 114 It will thwart or reverse social progress. In a world of ubiquitous
monitoring, there is no space for personal exploration, and no space to
challenge social norms, either. Living in fear, there is no genuine freedom.
6. But creeping surveillance is hard to stop, because of interlocking corporate
and governmental interests. 115 Cryptography offers at least some hope. With
it, one might carve out a space free of power’s reach.`)
	err = ratchetChanB.Write(msg2)
	assert.NoError(err)

	msg2Read, err := ratchetChanA.Read()
	assert.NoError(err)
	assert.Equal(msg2, msg2Read)
}

func TestSerializationOfTheDoubleRatchet(t *testing.T) {
	assert := assert.New(t)

	chanA, chanB := newTestSpoolChannelPair(t)

	ratchetChanA, err := NewUnreliableDoubleRatchetChannel(chanA)
	assert.NoError(err)
	ratchetChanB, err := NewUnreliableDoubleRatchetChannel(chanB)
	assert.NoError(err)

	kxA, err := ratchetChanA.KeyExchange()
	assert.NoError(err)
	kxB, err := ratchetChanB.KeyExchange()
	assert.NoError(err)

	err = ratchetChanA.ProcessKeyExchange(kxB)
	assert.NoError(err)
	err = ratchetChanB.ProcessKeyExchange(kxA)
	assert.NoError(err)

	msg1 := []byte("test message one")
	err = ratchetChanA.Write(msg1)
	assert.NoError(err)

	msg1Read, err := ratchetChanB.Read()
	assert.NoError(err)
	assert.Equal(msg1, msg1Read)

	blobA, err := ratchetChanA.Save()
	assert.NoError(err)
	ratchetChanC, err := LoadUnreliableDoubleRatchetChannel(blobA, ratchetChanA.SpoolCh.spoolService)
	assert.NoError(err)

	msg2 := []byte("test message two")
	err = ratchetChanC.Write(msg2)
	assert.NoError(err)

	msg2Read, err := ratchetChanB.Read()
	assert.NoError(err)
	assert.Equal(msg2, msg2Read)

}

func TestDoubleRatchetPadding(t *testing.T) {
	assert := assert.New(t)

	chanA, chanB := newTestSpoolChannelPair(t)

	ratchetChanA, err := NewUnreliableDoubleRatchetChannel(chanA)
	assert.NoError(err)
	ratchetChanB, err := NewUnreliableDoubleRatchetChannel(chanB)
	assert.NoError(err)

	kxA, err := ratchetChanA.KeyExchange()
	assert.NoError(err)
	kxB, err := ratchetChanB.KeyExchange()
	assert.NoError(err)

	err = ratchetChanA.ProcessKeyExchange(kxB)
	assert.NoError(err)
	err = ratchetChanB.ProcessKeyExchange(kxA)
	assert.NoError(err)

	msg1 := []byte("test message one")
	err = ratchetChanA.Write(msg1)
	assert.NoError(err)

	mock, ok := chanA.spoolService.(*mockRemoteSpool)
	assert.True(ok)

	spoolID := [common.SpoolIDSize]byte{}
	copy(spoolID[:], chanA.writerChan.SpoolID)
	message := mock.spool[spoolID][uint32(mock.count-1)]
	t.Logf("spool id %x", chanA.writerChan.SpoolID)
	t.Logf("message len is %d must be equal or less than %d", len(message), constants.UserForwardPayloadLength)
	if len(message) > constants.UserForwardPayloadLength {
		t.Fatal("ciphertext length must not exceed Sphinx packet payload maximum")
	}
}
