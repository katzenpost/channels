// spool_channel.go - remote spool based mixnet communications channel
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

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/memspool/client"
	"github.com/ugorji/go/codec"
)

var cborHandle = new(codec.CborHandle)

type UnreliableSpoolWriterChannel struct {
	SpoolID       []byte
	SpoolReceiver string
	SpoolProvider string
}

func (w *UnreliableSpoolWriterChannel) Write(spool client.SpoolService, message []byte) error {
	err := spool.AppendToSpool(w.SpoolID[:], message, w.SpoolReceiver, w.SpoolProvider)
	return err
}

type UnreliableSpoolReaderChannel struct {
	SpoolPrivateKey *eddsa.PrivateKey
	SpoolID         []byte
	SpoolReceiver   string
	SpoolProvider   string
	ReadOffset      uint32
}

func NewUnreliableSpoolReaderChannel(spoolReceiver, spoolProvider string, spool client.SpoolService) (*UnreliableSpoolReaderChannel, error) {
	// generate keys
	spoolPrivateKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}

	// create spool on remote Provider
	spoolID, err := spool.CreateSpool(spoolPrivateKey, spoolReceiver, spoolProvider)
	if err != nil {
		return nil, err
	}

	return &UnreliableSpoolReaderChannel{
		SpoolPrivateKey: spoolPrivateKey,
		SpoolID:         spoolID,
		SpoolReceiver:   spoolReceiver,
		SpoolProvider:   spoolProvider,
		ReadOffset:      1,
	}, nil
}

func (s *UnreliableSpoolReaderChannel) GetSpoolWriter() *UnreliableSpoolWriterChannel {
	return &UnreliableSpoolWriterChannel{
		SpoolID:       s.SpoolID,
		SpoolReceiver: s.SpoolReceiver,
		SpoolProvider: s.SpoolProvider,
	}
}

func (s *UnreliableSpoolReaderChannel) Read(spool client.SpoolService) ([]byte, error) {
	spoolResponse, err := spool.ReadFromSpool(s.SpoolID[:], s.ReadOffset, s.SpoolPrivateKey, s.SpoolReceiver, s.SpoolProvider)
	if err != nil {
		return nil, err
	}
	if spoolResponse.Status != "OK" {
		return nil, errors.New(spoolResponse.Status)
	}
	s.ReadOffset++

	return spoolResponse.Message, nil
}

type SerializedUnreliableSpoolChannel struct {
	WriterChan *UnreliableSpoolWriterChannel
	ReaderChan *UnreliableSpoolReaderChannel
}

type UnreliableSpoolChannel struct {
	spoolService client.SpoolService
	writerChan   *UnreliableSpoolWriterChannel
	readerChan   *UnreliableSpoolReaderChannel
}

func LoadUnreliableSpoolChannel(data []byte, spoolService client.SpoolService) (*UnreliableSpoolChannel, error) {
	ch := new(UnreliableSpoolChannel)
	err := ch.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}
	ch.SetSpoolService(spoolService)
	return ch, nil
}

func NewUnreliableSpoolChannel(spoolReceiver, spoolProvider string, spool client.SpoolService) (*UnreliableSpoolChannel, error) {
	readerChan, err := NewUnreliableSpoolReaderChannel(spoolReceiver, spoolProvider, spool)
	if err != nil {
		return nil, err
	}
	return &UnreliableSpoolChannel{
		spoolService: spool,
		readerChan:   readerChan,
		writerChan:   nil,
	}, nil
}

func (s *UnreliableSpoolChannel) GetSpoolWriter() *UnreliableSpoolWriterChannel {
	return s.readerChan.GetSpoolWriter()
}

func (s *UnreliableSpoolChannel) WithRemoteWriter(writer *UnreliableSpoolWriterChannel) error {
	if writer == nil {
		return errors.New("writer must not be nil")
	}
	if s.writerChan != nil {
		return errors.New("writerChan must be nil")
	}
	s.writerChan = writer
	return nil
}

func (s *UnreliableSpoolChannel) Read() ([]byte, error) {
	return s.readerChan.Read(s.spoolService)
}

func (s *UnreliableSpoolChannel) Write(message []byte) error {
	if s.writerChan == nil {
		return errors.New("writerChan must not be nil")
	}
	return s.writerChan.Write(s.spoolService, message)
}

func (s *UnreliableSpoolChannel) MarshalBinary() ([]byte, error) {
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, cborHandle)
	solo := SerializedUnreliableSpoolChannel{
		WriterChan: s.writerChan,
		ReaderChan: s.readerChan,
	}
	if err := enc.Encode(solo); err != nil {
		return nil, err
	}
	return serialized, nil
}

func (s *UnreliableSpoolChannel) UnmarshalBinary(data []byte) error {
	n := new(SerializedUnreliableSpoolChannel)
	err := codec.NewDecoderBytes(data, cborHandle).Decode(&n)
	if err != nil {
		return err
	}
	s.writerChan = n.WriterChan
	s.readerChan = n.ReaderChan
	return nil
}

func (s *UnreliableSpoolChannel) SetSpoolService(spoolService client.SpoolService) {
	s.spoolService = spoolService
}

func (s *UnreliableSpoolChannel) Save() ([]byte, error) {
	return s.MarshalBinary()
}
