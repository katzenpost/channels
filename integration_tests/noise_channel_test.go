// client_test.go - Katzenpost client library tests.
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

// Package client provides a Katzenpost client library.
package client

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/katzenpost/channels"
	"github.com/katzenpost/client"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/kimchi"
	"github.com/stretchr/testify/assert"
)

const basePort = 30000

func TestNoiseChannel(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := kimchi.NewKimchi(basePort+400, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
		t.Logf("Time is up!")

		aliceCfg, err := k.GetClientConfig()
		assert.NoError(err)
		aliceClient, err := client.New(aliceCfg)
		assert.NoError(err)
		go k.LogTailer(aliceCfg.Account.User, filepath.Join(aliceCfg.Proxy.DataDir, aliceCfg.Logging.File))
		aliceSession, err := aliceClient.NewSession()
		assert.NoError(err)
		serviceDesc, err := aliceSession.GetService("spool")
		assert.NoError(err)
		assert.NotNil(serviceDesc)
		chanA, err := channels.NewUnreliableNoiseChannel(serviceDesc.Name, serviceDesc.Provider, aliceSession)
		assert.NoError(err)

		bobCfg, err := k.GetClientConfig()
		assert.NoError(err)
		bobClient, err := client.New(bobCfg)
		assert.NoError(err)
		go k.LogTailer(bobCfg.Account.User, filepath.Join(bobCfg.Proxy.DataDir, bobCfg.Logging.File))
		bobSession, err := bobClient.NewSession()
		assert.NoError(err)
		serviceDesc, err = bobSession.GetService("spool")
		assert.NoError(err)
		chanB, err := channels.NewUnreliableNoiseChannel(serviceDesc.Name, serviceDesc.Provider, bobSession)
		assert.NoError(err)

		chanADescriptor := chanA.DescribeWriter()
		err = chanB.WithRemoteWriterDescriptor(chanADescriptor)
		assert.NoError(err)

		chanBDescriptor := chanB.DescribeWriter()
		err = chanA.WithRemoteWriterDescriptor(chanBDescriptor)
		assert.NoError(err)

		msg1 := []byte(`Stripping out the politics. But as academics gravitated to cryptography, they
tended to sanitize it, stripping it of ostensible connectedness to power. Applied
and privacy-related work drifted outside of the field’s core venues, the IACR
conferences. It is as though a chemical synthesis would take place, transforming
this powerful powder into harmless dust.`)
		err = chanA.Write(msg1)
		assert.NoError(err)

		msg1Read, err := chanB.Read()
		assert.NoError(err)
		assert.Equal(msg1, msg1Read)

		msg2 := []byte(`Consider that there is now a conference named “Real World Cryptography”
(RWC). 53 There is humor—but maybe gallows humor—that a field with a genesis
and capability as real-world as ours should find reason to create a venue so
named. 54 Ask a colleague in Graphics or Cloud Computing how it would fly in
their community if someone started a conference called Real World Computer
Graphics (RWCG 2015) or Real World Cloud Computing (RWCC 2016). They
will laugh.`)
		err = chanB.Write(msg2)
		assert.NoError(err)

		msg2Read, err := chanA.Read()
		assert.NoError(err)
		assert.Equal(msg2, msg2Read)

		bobClient.Shutdown()
		bobClient.Wait()

		aliceClient.Shutdown()
		aliceClient.Wait()
	}()

	k.Wait()
	t.Logf("Terminated.")
}
