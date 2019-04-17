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
	"github.com/katzenpost/core/crypto/rand"
	ratchet "github.com/katzenpost/doubleratchet"
)

const DoubleRatchetOverhead = 144

type UnreliableDoubleRatchetChannel struct {
	noiseCh *UnreliableNoiseChannel
	ratchet *ratchet.Ratchet
}

func NewUnreliableDoubleRatchetChannel(noiseCh *UnreliableNoiseChannel) (*UnreliableDoubleRatchetChannel, error) {
	ratchet, err := ratchet.New(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &UnreliableDoubleRatchetChannel{
		noiseCh: noiseCh,
		ratchet: ratchet,
	}, nil
}

func (r *UnreliableDoubleRatchetChannel) ProcessKeyExchange(kxsBytes []byte) error {
	return r.ratchet.ProcessKeyExchange(kxsBytes)
}

func (r *UnreliableDoubleRatchetChannel) KeyExchange() ([]byte, error) {
	return r.ratchet.CreateKeyExchange()
}

func (r *UnreliableDoubleRatchetChannel) Write(message []byte) error {
	ciphertext := r.ratchet.Encrypt(nil, message)
	return r.noiseCh.Write(ciphertext)
}

func (r *UnreliableDoubleRatchetChannel) Read() ([]byte, error) {
	ciphertext, err := r.noiseCh.Read()
	if err != nil {
		return nil, err
	}
	return r.ratchet.Decrypt(ciphertext)
}
