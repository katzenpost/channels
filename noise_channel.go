// noise_channel.go - Noise based mixnet communications channel
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

	"github.com/katzenpost/client/multispool"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/minclient/block"
)

const (
	SpoolService = "spool"
)

type RemoteSpool interface {
	CreateSpool(privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) ([]byte, error)
	ReadFromSpool(spoolID []byte, count uint32, privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) (*multispool.SpoolResponse, error)
	AppendToSpool(spoolID []byte, message []byte, spoolReceiver string, spoolProvider string) error
}

type NoiseWriterDescriptor struct {
	spoolID              []byte
	spoolReceiver        string
	spoolProvider        string
	remoteNoisePublicKey *ecdh.PublicKey
}

type UnreliableNoiseWriterChannel struct {
	spoolID              []byte
	spoolReceiver        string
	spoolProvider        string
	remoteNoisePublicKey *ecdh.PublicKey
	noisePrivateKey      *ecdh.PrivateKey
}

func (w *UnreliableNoiseWriterChannel) Write(spool RemoteSpool, message []byte) error {
	mesgID := [block.MessageIDLength]byte{}
	_, err := rand.NewMath().Read(mesgID[:])
	if err != nil {
		return nil
	}
	blocks, err := block.EncryptMessage(&mesgID, message, w.noisePrivateKey, w.remoteNoisePublicKey)
	if err != nil {
		return nil
	}
	if len(blocks) != 1 {
		return errors.New("message fragmentation not yet supported")
	}
	err = spool.AppendToSpool(w.spoolID[:], blocks[0], w.spoolReceiver, w.spoolProvider)
	return err
}

type UnreliableNoiseReaderChannel struct {
	spoolPrivateKey      *eddsa.PrivateKey
	spoolID              []byte
	spoolReceiver        string
	spoolProvider        string
	readOffset           uint32
	noisePrivateKey      *ecdh.PrivateKey
	remoteNoisePublicKey *ecdh.PublicKey
}

func NewUnreliableNoiseReaderChannel(spoolReceiver, spoolProvider string, spool RemoteSpool) (*UnreliableNoiseReaderChannel, error) {
	// generate keys
	spoolPrivateKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	noisePrivateKey, err := ecdh.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}

	// create spool on remote Provider
	spoolID, err := spool.CreateSpool(spoolPrivateKey, spoolReceiver, spoolProvider)
	if err != nil {
		return nil, err
	}

	return &UnreliableNoiseReaderChannel{
		spoolPrivateKey:      spoolPrivateKey,
		spoolID:              spoolID,
		spoolReceiver:        spoolReceiver,
		spoolProvider:        spoolProvider,
		readOffset:           1,
		noisePrivateKey:      noisePrivateKey,
		remoteNoisePublicKey: nil,
	}, nil
}

func (r *UnreliableNoiseReaderChannel) DescribeWriter() *NoiseWriterDescriptor {
	return &NoiseWriterDescriptor{
		spoolID:              r.spoolID,
		spoolReceiver:        r.spoolReceiver,
		spoolProvider:        r.spoolProvider,
		remoteNoisePublicKey: r.noisePrivateKey.PublicKey(),
	}
}

func (s *UnreliableNoiseReaderChannel) Read(spool RemoteSpool) ([]byte, error) {
	spoolResponse, err := spool.ReadFromSpool(s.spoolID[:], s.readOffset, s.spoolPrivateKey, s.spoolReceiver, s.spoolProvider)
	if err != nil {
		return nil, err
	}
	if spoolResponse.Status != "OK" {
		return nil, errors.New(spoolResponse.Status)
	}
	s.readOffset++
	block, pubKey, err := block.DecryptBlock(spoolResponse.Message, s.noisePrivateKey)
	if err != nil {
		return nil, err
	}
	if !s.remoteNoisePublicKey.Equal(pubKey) {
		return nil, errors.New("wtf, wrong partner Noise X key")
	}
	if block.TotalBlocks != 1 {
		return nil, errors.New("block error, one block per message required")
	}
	return block.Payload, nil
}

type UnreliableNoiseChannel struct {
	spool      RemoteSpool
	writerChan *UnreliableNoiseWriterChannel
	readerChan *UnreliableNoiseReaderChannel
}

func NewUnreliableNoiseChannel(spoolReceiver, spoolProvider string, spool RemoteSpool) (*UnreliableNoiseChannel, error) {
	readerChan, err := NewUnreliableNoiseReaderChannel(spoolReceiver, spoolProvider, spool)
	if err != nil {
		return nil, err
	}
	return &UnreliableNoiseChannel{
		spool:      spool,
		readerChan: readerChan,
		writerChan: nil,
	}, nil
}

func NewUnreliableNoiseChannelWithRemoteDescriptor(spoolReceiver, spoolProvider string, spool RemoteSpool, writerDesc *NoiseWriterDescriptor) (*UnreliableNoiseChannel, error) {
	noiseChan, err := NewUnreliableNoiseChannel(spoolReceiver, spoolProvider, spool)
	if err != nil {
		return nil, err
	}
	err = noiseChan.WithRemoteWriterDescriptor(writerDesc)
	if err != nil {
		return nil, err
	}
	return noiseChan, nil
}

func (s *UnreliableNoiseChannel) DescribeWriter() *NoiseWriterDescriptor {
	return s.readerChan.DescribeWriter()
}

func (s *UnreliableNoiseChannel) WithRemoteWriterDescriptor(writerDesc *NoiseWriterDescriptor) error {
	if s.writerChan != nil {
		return errors.New("writerChan must be nil")
	}
	s.writerChan = &UnreliableNoiseWriterChannel{
		spoolID:              writerDesc.spoolID,
		spoolReceiver:        writerDesc.spoolReceiver,
		spoolProvider:        writerDesc.spoolProvider,
		remoteNoisePublicKey: writerDesc.remoteNoisePublicKey,
		noisePrivateKey:      s.readerChan.noisePrivateKey,
	}
	s.readerChan.remoteNoisePublicKey = writerDesc.remoteNoisePublicKey
	return nil
}

func (s *UnreliableNoiseChannel) Read() ([]byte, error) {
	return s.readerChan.Read(s.spool)
}

func (s *UnreliableNoiseChannel) Write(message []byte) error {
	if s.writerChan == nil {
		return errors.New("writerChan must not be nil")
	}
	return s.writerChan.Write(s.spool, message)
}
