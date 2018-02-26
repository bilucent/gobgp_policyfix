// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package table

import (
  "fmt"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestTableDeleteDestByNlri(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:815, table_test.go:TestTableDeleteDestByNlri(t>>>")
	peerT := TableCreatePeer()
	pathT := TableCreatePath(peerT)
	ipv4t := NewTable(bgp.RF_IPv4_UC)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.GetNlri())
		dest := NewDestination(path.GetNlri(), 0)
		ipv4t.setDestination(tableKey, dest)
	}
	tableKey := ipv4t.tableKey(pathT[0].GetNlri())
	gdest := ipv4t.GetDestination(tableKey)
	rdest := ipv4t.deleteDestByNlri(pathT[0].GetNlri())
	assert.Equal(t, rdest, gdest)
}

func TestTableDeleteDest(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:816, table_test.go:TestTableDeleteDest(t>>>")
	peerT := TableCreatePeer()
	pathT := TableCreatePath(peerT)
	ipv4t := NewTable(bgp.RF_IPv4_UC)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.GetNlri())
		dest := NewDestination(path.GetNlri(), 0)
		ipv4t.setDestination(tableKey, dest)
	}
	tableKey := ipv4t.tableKey(pathT[0].GetNlri())
	dest := NewDestination(pathT[0].GetNlri(), 0)
	ipv4t.setDestination(tableKey, dest)
	ipv4t.deleteDest(dest)
	gdest := ipv4t.GetDestination(tableKey)
	assert.Nil(t, gdest)
}

func TestTableGetRouteFamily(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:817, table_test.go:TestTableGetRouteFamily(t>>>")
	ipv4t := NewTable(bgp.RF_IPv4_UC)
	rf := ipv4t.GetRoutefamily()
	assert.Equal(t, rf, bgp.RF_IPv4_UC)
}

func TestTableSetDestinations(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:818, table_test.go:TestTableSetDestinations(t>>>")
	peerT := TableCreatePeer()
	pathT := TableCreatePath(peerT)
	ipv4t := NewTable(bgp.RF_IPv4_UC)
	destinations := make(map[string]*Destination)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.GetNlri())
		dest := NewDestination(path.GetNlri(), 0)
		destinations[tableKey] = dest
	}
	ipv4t.setDestinations(destinations)
	ds := ipv4t.GetDestinations()
	assert.Equal(t, ds, destinations)
}
func TestTableGetDestinations(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:819, table_test.go:TestTableGetDestinations(t>>>")
	peerT := DestCreatePeer()
	pathT := DestCreatePath(peerT)
	ipv4t := NewTable(bgp.RF_IPv4_UC)
	destinations := make(map[string]*Destination)
	for _, path := range pathT {
		tableKey := ipv4t.tableKey(path.GetNlri())
		dest := NewDestination(path.GetNlri(), 0)
		destinations[tableKey] = dest
	}
	ipv4t.setDestinations(destinations)
	ds := ipv4t.GetDestinations()
	assert.Equal(t, ds, destinations)
}

func TableCreatePeer() []*PeerInfo { 
   fmt.Print("<<<DEJDEJ id:820, table_test.go:TableCreatePeer()>>>")
	peerT1 := &PeerInfo{AS: 65000}
	peerT2 := &PeerInfo{AS: 65001}
	peerT3 := &PeerInfo{AS: 65002}
	peerT := []*PeerInfo{peerT1, peerT2, peerT3}
	return peerT
}

func TableCreatePath(peerT []*PeerInfo) []*Path { 
   fmt.Print("<<<DEJDEJ id:821, table_test.go:TableCreatePath(peerT>>>")
	bgpMsgT1 := updateMsgT1()
	bgpMsgT2 := updateMsgT2()
	bgpMsgT3 := updateMsgT3()
	pathT := make([]*Path, 3)
	for i, msg := range []*bgp.BGPMessage{bgpMsgT1, bgpMsgT2, bgpMsgT3} {
		updateMsgT := msg.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgT.NLRI
		pathAttributes := updateMsgT.PathAttributes
		nlri_info := nlriList[0]
		pathT[i] = NewPath(peerT[i], nlri_info, false, pathAttributes, time.Now(), false)
	}
	return pathT
}

func updateMsgT1() *bgp.BGPMessage { 
   fmt.Print("<<<DEJDEJ id:822, table_test.go:updateMsgT1()>>>")

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65000})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")
	med := bgp.NewPathAttributeMultiExitDisc(0)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
}

func updateMsgT2() *bgp.BGPMessage { 
   fmt.Print("<<<DEJDEJ id:823, table_test.go:updateMsgT2()>>>")

	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.100.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "20.20.20.0")}
	return bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
}
func updateMsgT3() *bgp.BGPMessage { 
   fmt.Print("<<<DEJDEJ id:824, table_test.go:updateMsgT3()>>>")
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAsPathParam(2, []uint16{65100})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.150.1")
	med := bgp.NewPathAttributeMultiExitDisc(100)

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
		med,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "30.30.30.0")}
	w1 := bgp.NewIPAddrPrefix(23, "40.40.40.0")
	withdrawnRoutes := []*bgp.IPAddrPrefix{w1}
	return bgp.NewBGPUpdateMessage(withdrawnRoutes, pathAttributes, nlri)
}
