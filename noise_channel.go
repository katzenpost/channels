// noise.go - Noise based channel
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
	"errors"

	"github.com/katzenpost/client/session"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/minclient/block"
)

const (
	SpoolService = "spool"
)

type UnreliableSpoolReader struct {
	session               *session.Session
	spoolProvider         string
	spoolReceiver         string
	spoolID               []byte
	spoolPrivateKey       *eddsa.PrivateKey
	noisePrivateKey       *ecdh.PrivateKey
	partnerNoisePublicKey *ecdh.PublicKey
	spoolIndex            uint32
}

func CreateUnreliableSpoolReader(session *session.Session, partnerNoisePublicKey *ecdh.PublicKey) (*UnreliableSpoolReader, error) {
	descriptor, err := session.GetService(SpoolService)
	if err != nil {
		return nil, err
	}
	spoolPrivateKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	noisePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	spoolID, err := session.CreateSpool(spoolPrivateKey, descriptor.Name, descriptor.Provider)
	if err != nil {
		return nil, err
	}
	return &UnreliableSpoolReader{
		session:               session,
		spoolProvider:         descriptor.Provider,
		spoolReceiver:         descriptor.Name,
		spoolID:               spoolID,
		spoolPrivateKey:       spoolPrivateKey,
		noisePrivateKey:       noisePrivateKey,
		partnerNoisePublicKey: partnerNoisePublicKey,
		spoolIndex:            1,
	}, nil
}

func (r *UnreliableSpoolReader) Read() ([]byte, error) {
	spoolResponse, err := r.session.ReadFromSpool(r.spoolID[:], r.spoolIndex, r.spoolPrivateKey, r.spoolReceiver, r.spoolProvider)
	if err != nil {
		return nil, err
	}
	if spoolResponse.Status != "OK" {
		return nil, errors.New(spoolResponse.Status)
	}
	r.spoolIndex++
	block, pubKey, err := block.DecryptBlock(spoolResponse.Message, r.noisePrivateKey)
	if err != nil {
		return nil, err
	}
	if !r.partnerNoisePublicKey.Equal(pubKey) {
		return nil, errors.New("wtf, wrong partner Noise X key")
	}
	if block.TotalBlocks != 1 {
		return nil, errors.New("block error, one block per message required")
	}
	return block.Payload, nil
}

type UnreliableSpoolWriter struct {
	session               *session.Session
	spoolProvider         string
	spoolReceiver         string
	spoolID               []byte
	noisePrivateKey       *ecdh.PrivateKey
	partnerNoisePublicKey *ecdh.PublicKey
}

func CreateUnreliableSpoolWriter(session *session.Session, spoolID []byte, spoolReceiver string, spoolProvider string, partnerNoisePublicKey *ecdh.PublicKey) (*UnreliableSpoolWriter, error) {
	noisePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &UnreliableSpoolWriter{
		session:               session,
		spoolProvider:         spoolProvider,
		spoolReceiver:         spoolReceiver,
		spoolID:               spoolID,
		noisePrivateKey:       noisePrivateKey,
		partnerNoisePublicKey: partnerNoisePublicKey,
	}, nil
}

func (r *UnreliableSpoolWriter) Write(message []byte) error {
	mesgID := [block.MessageIDLength]byte{}
	_, err := rand.NewMath().Read(mesgID[:])
	if err != nil {
		return nil
	}
	blocks, err := block.EncryptMessage(&mesgID, message, r.noisePrivateKey, r.partnerNoisePublicKey)
	if err != nil {
		return nil
	}
	if len(blocks) != 1 {
		return errors.New("message fragmentation not yet supported")
	}
	err = r.session.AppendToSpool(r.spoolID[:], message, r.spoolReceiver, r.spoolProvider)
	return err
}

type UnreliableNoiseChannel struct {
	reader *UnreliableSpoolReader
	writer *UnreliableSpoolWriter
}

func (s *UnreliableNoiseChannel) Read() ([]byte, error) {
	return s.reader.Read()
}

func (s *UnreliableNoiseChannel) Write(message []byte) error {
	return s.writer.Write(message)
}
