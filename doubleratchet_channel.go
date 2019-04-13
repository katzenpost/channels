// doubleratchet_channel.go - Signal Double Ratchet based mixnet communications channel
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
	"encoding/binary"

	"github.com/katzenpost/core/crypto/rand"
	"github.com/status-im/doubleratchet"
)

const DoubleRatchetOverhead = 144

type UnreliableDoubleRatchetChannelDescriptor struct {
	publicKey        doubleratchet.Key
	sharedKey        [32]byte
	sharedHeaderKeyA [32]byte
	sharedHeaderKeyB [32]byte
}

type UnreliableDoubleRatchetChannel struct {
	noiseCh *UnreliableNoiseChannel

	keyPair          doubleratchet.DHPair
	sharedKey        [32]byte
	sharedHeaderKeyA [32]byte
	sharedHeaderKeyB [32]byte

	ratchet doubleratchet.SessionHE
}

func NewUnreliableDoubleRatchetChannel(noiseCh *UnreliableNoiseChannel) (*UnreliableDoubleRatchetChannel, error) {
	sk := [32]byte{}
	_, err := rand.Reader.Read(sk[:])
	if err != nil {
		return nil, err
	}
	sharedHka := [32]byte{}
	_, err = rand.Reader.Read(sharedHka[:])
	if err != nil {
		return nil, err
	}
	sharedNhkb := [32]byte{}
	_, err = rand.Reader.Read(sharedNhkb[:])
	if err != nil {
		return nil, err
	}
	keyPair, err := doubleratchet.DefaultCrypto{}.GenerateDH()
	if err != nil {
		return nil, err
	}
	ratchet, err := doubleratchet.NewHE(sk, sharedHka, sharedNhkb, keyPair)
	return &UnreliableDoubleRatchetChannel{
		noiseCh:          noiseCh,
		sharedKey:        sk,
		sharedHeaderKeyA: sharedHka,
		sharedHeaderKeyB: sharedNhkb,
		keyPair:          keyPair,
		ratchet:          ratchet,
	}, nil
}

func NewUnreliableDoubleRatchetChannelWithRemoteDescriptor(noiseCh *UnreliableNoiseChannel, desc *UnreliableDoubleRatchetChannelDescriptor) (*UnreliableDoubleRatchetChannel, error) {
	ratchet, err := doubleratchet.NewHEWithRemoteKey(desc.sharedKey, desc.sharedHeaderKeyA, desc.sharedHeaderKeyB, desc.publicKey)
	if err != nil {
		return nil, err
	}

	return &UnreliableDoubleRatchetChannel{
		noiseCh:          noiseCh,
		sharedKey:        desc.sharedKey,
		sharedHeaderKeyA: desc.sharedHeaderKeyA,
		sharedHeaderKeyB: desc.sharedHeaderKeyB,
		ratchet:          ratchet,
	}, nil
}

func (r *UnreliableDoubleRatchetChannel) GetDescriptor() *UnreliableDoubleRatchetChannelDescriptor {
	return &UnreliableDoubleRatchetChannelDescriptor{
		publicKey:        r.keyPair.PublicKey(),
		sharedKey:        r.sharedKey,
		sharedHeaderKeyA: r.sharedHeaderKeyA,
		sharedHeaderKeyB: r.sharedHeaderKeyB,
	}
}

func (r *UnreliableDoubleRatchetChannel) Write(message []byte) error {
	mesgHE := r.ratchet.RatchetEncrypt(message, nil)
	ciphertext := make([]byte, len(mesgHE.Header)+len(mesgHE.Ciphertext)+8)
	binary.BigEndian.PutUint32(ciphertext[:4], uint32(len(mesgHE.Header)))
	copy(ciphertext[4:], mesgHE.Header)
	binary.BigEndian.PutUint32(ciphertext[4+len(mesgHE.Header):], uint32(len(mesgHE.Ciphertext)))
	copy(ciphertext[4+len(mesgHE.Header)+4:], mesgHE.Ciphertext)
	return r.noiseCh.Write(ciphertext)
}

func (r *UnreliableDoubleRatchetChannel) Read() ([]byte, error) {
	mesgRaw, err := r.noiseCh.Read()
	if err != nil {
		return nil, err
	}
	headerLen := binary.BigEndian.Uint32(mesgRaw[:4])
	ciphertextLen := binary.BigEndian.Uint32(mesgRaw[4+headerLen : 4+headerLen+4])
	mesgHE := &doubleratchet.MessageHE{
		Header:     mesgRaw[4 : headerLen+4],
		Ciphertext: mesgRaw[4+headerLen+4 : ciphertextLen+4+headerLen+4],
	}
	return r.ratchet.RatchetDecrypt(*mesgHE, nil)
}
