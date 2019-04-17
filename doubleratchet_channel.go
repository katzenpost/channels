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
	"github.com/katzenpost/client/session"
	"github.com/katzenpost/core/crypto/rand"
	ratchet "github.com/katzenpost/doubleratchet"
	"github.com/ugorji/go/codec"
)

const DoubleRatchetOverhead = 144

type UnreliableDoubleRatchetChannel struct {
	NoiseCh *UnreliableNoiseChannel
	Ratchet *ratchet.Ratchet
}

func NewUnreliableDoubleRatchetChannel(noiseCh *UnreliableNoiseChannel) (*UnreliableDoubleRatchetChannel, error) {
	ratchet, err := ratchet.New(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &UnreliableDoubleRatchetChannel{
		NoiseCh: noiseCh,
		Ratchet: ratchet,
	}, nil
}

func (r *UnreliableDoubleRatchetChannel) ProcessKeyExchange(kxsBytes []byte) error {
	return r.Ratchet.ProcessKeyExchange(kxsBytes)
}

func (r *UnreliableDoubleRatchetChannel) KeyExchange() ([]byte, error) {
	return r.Ratchet.CreateKeyExchange()
}

func (r *UnreliableDoubleRatchetChannel) Write(message []byte) error {
	ciphertext := r.Ratchet.Encrypt(nil, message)
	return r.NoiseCh.Write(ciphertext)
}

func (r *UnreliableDoubleRatchetChannel) Read() ([]byte, error) {
	ciphertext, err := r.NoiseCh.Read()
	if err != nil {
		return nil, err
	}
	return r.Ratchet.Decrypt(ciphertext)
}

func (s *UnreliableDoubleRatchetChannel) Save() ([]byte, error) {
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, cborHandle)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return serialized, nil
}

func Load(data []byte, spoolService session.SpoolService) (*UnreliableDoubleRatchetChannel, error) {
	var err error
	s := new(UnreliableDoubleRatchetChannel)
	s.Ratchet, err = ratchet.New(rand.Reader)
	if err != nil {
		return nil, err
	}
	err = codec.NewDecoderBytes(data, cborHandle).Decode(s)
	if err != nil {
		return nil, err
	}
	s.NoiseCh.SetSpoolService(spoolService)
	return s, nil
}
