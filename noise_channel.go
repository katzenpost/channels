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
	"github.com/katzenpost/noise"
	"github.com/ugorji/go/codec"
)

const (
	SpoolService = "spool"

	NoiseOverhead = keyLength + macLength + keyLength + macLength // e, es, s, ss
	keyLength     = 32
	macLength     = 16
)

var cborHandle = new(codec.CborHandle)

type RemoteSpool interface {
	CreateSpool(privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) ([]byte, error)
	ReadFromSpool(spoolID []byte, count uint32, privateKey *eddsa.PrivateKey, spoolReceiver string, spoolProvider string) (*multispool.SpoolResponse, error)
	AppendToSpool(spoolID []byte, message []byte, spoolReceiver string, spoolProvider string) error
}

type NoiseWriterDescriptor struct {
	SpoolID              []byte
	SpoolReceiver        string
	SpoolProvider        string
	RemoteNoisePublicKey *ecdh.PublicKey
}

type UnreliableNoiseWriterChannel struct {
	SpoolID              []byte
	SpoolReceiver        string
	SpoolProvider        string
	RemoteNoisePublicKey *ecdh.PublicKey
	NoisePrivateKey      *ecdh.PrivateKey
}

func (w *UnreliableNoiseWriterChannel) Write(spool RemoteSpool, message []byte) error {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	senderDH := noise.DHKey{
		Private: w.NoisePrivateKey.Bytes(),
		Public:  w.NoisePrivateKey.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeX,
		Initiator:     true,
		StaticKeypair: senderDH,
		PeerStatic:    w.RemoteNoisePublicKey.Bytes(),
	})
	if err != nil {
		return err
	}
	ciphertext, _, _, err := hs.WriteMessage(nil, message)
	if err != nil {
		return err
	}
	err = spool.AppendToSpool(w.SpoolID[:], ciphertext, w.SpoolReceiver, w.SpoolProvider)
	return err
}

type UnreliableNoiseReaderChannel struct {
	SpoolPrivateKey      *eddsa.PrivateKey
	SpoolID              []byte
	SpoolReceiver        string
	SpoolProvider        string
	ReadOffset           uint32
	NoisePrivateKey      *ecdh.PrivateKey
	RemoteNoisePublicKey *ecdh.PublicKey
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
		SpoolPrivateKey:      spoolPrivateKey,
		SpoolID:              spoolID,
		SpoolReceiver:        spoolReceiver,
		SpoolProvider:        spoolProvider,
		ReadOffset:           1,
		NoisePrivateKey:      noisePrivateKey,
		RemoteNoisePublicKey: nil,
	}, nil
}

func (r *UnreliableNoiseReaderChannel) DescribeWriter() *NoiseWriterDescriptor {
	return &NoiseWriterDescriptor{
		SpoolID:              r.SpoolID,
		SpoolReceiver:        r.SpoolReceiver,
		SpoolProvider:        r.SpoolProvider,
		RemoteNoisePublicKey: r.NoisePrivateKey.PublicKey(),
	}
}

func (s *UnreliableNoiseReaderChannel) Read(spool RemoteSpool) ([]byte, error) {
	spoolResponse, err := spool.ReadFromSpool(s.SpoolID[:], s.ReadOffset, s.SpoolPrivateKey, s.SpoolReceiver, s.SpoolProvider)
	if err != nil {
		return nil, err
	}
	if spoolResponse.Status != "OK" {
		return nil, errors.New(spoolResponse.Status)
	}
	s.ReadOffset++

	// Decrypt the ciphertext into a plaintext.
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	recipientDH := noise.DHKey{
		Private: s.NoisePrivateKey.Bytes(),
		Public:  s.NoisePrivateKey.PublicKey().Bytes(),
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeX,
		Initiator:     false,
		StaticKeypair: recipientDH,
		PeerStatic:    nil,
	})
	if err != nil {
		return nil, err
	}
	plaintext, _, _, err := hs.ReadMessage(nil, spoolResponse.Message)
	if err != nil {
		return nil, err
	}

	senderPk := new(ecdh.PublicKey)
	if err = senderPk.FromBytes(hs.PeerStatic()); err != nil {
		panic("BUG: block: Failed to de-serialize peer static key: " + err.Error())
	}
	if !s.RemoteNoisePublicKey.Equal(senderPk) {
		return nil, errors.New("wtf, wrong partner Noise X key")
	}
	return plaintext, nil
}

type SerializedUnreliableNoiseChannel struct {
	WriterChan *UnreliableNoiseWriterChannel
	ReaderChan *UnreliableNoiseReaderChannel
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
		SpoolID:              writerDesc.SpoolID,
		SpoolReceiver:        writerDesc.SpoolReceiver,
		SpoolProvider:        writerDesc.SpoolProvider,
		RemoteNoisePublicKey: writerDesc.RemoteNoisePublicKey,
		NoisePrivateKey:      s.readerChan.NoisePrivateKey,
	}
	s.readerChan.RemoteNoisePublicKey = writerDesc.RemoteNoisePublicKey
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

func (s *UnreliableNoiseChannel) Serialize() ([]byte, error) {
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, cborHandle)
	solo := SerializedUnreliableNoiseChannel{
		WriterChan: s.writerChan,
		ReaderChan: s.readerChan,
	}
	if err := enc.Encode(solo); err != nil {
		return nil, err
	}
	return serialized, nil
}
