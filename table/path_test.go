// path_test.go
package table

import (
  "fmt"
	"testing"
	"time"

	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/stretchr/testify/assert"
)

func TestPathNewIPv4(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:993::path_test.go:TestPathNewIPv4(t>>>")
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv4p := NewPath(pathP[0].GetSource(), pathP[0].GetNlri(), true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv4p)
}

func TestPathNewIPv6(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:994::path_test.go:TestPathNewIPv6(t>>>")
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	ipv6p := NewPath(pathP[0].GetSource(), pathP[0].GetNlri(), true, pathP[0].GetPathAttrs(), time.Now(), false)
	assert.NotNil(t, ipv6p)
}

func TestPathGetNlri(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:995::path_test.go:TestPathGetNlri(t>>>")
	nlri := bgp.NewIPAddrPrefix(24, "13.2.3.2")
	pd := &Path{
		info: &originInfo{
			nlri: nlri,
		},
	}
	r_nlri := pd.GetNlri()
	assert.Equal(t, r_nlri, nlri)
}

func TestPathCreatePath(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:996::path_test.go:TestPathCreatePath(t>>>")
	peerP := PathCreatePeer()
	msg := updateMsgP1()
	updateMsgP := msg.Body.(*bgp.BGPUpdate)
	nlriList := updateMsgP.NLRI
	pathAttributes := updateMsgP.PathAttributes
	nlri_info := nlriList[0]
	path := NewPath(peerP[0], nlri_info, false, pathAttributes, time.Now(), false)
	assert.NotNil(t, path)

}

func TestPathGetPrefix(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:997::path_test.go:TestPathGetPrefix(t>>>")
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	prefix := "10.10.10.0/24"
	r_prefix := pathP[0].getPrefix()
	assert.Equal(t, r_prefix, prefix)
}

func TestPathGetAttribute(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:998::path_test.go:TestPathGetAttribute(t>>>")
	peerP := PathCreatePeer()
	pathP := PathCreatePath(peerP)
	nh := "192.168.50.1"
	pa := pathP[0].getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	r_nh := pa.(*bgp.PathAttributeNextHop).Value.String()
	assert.Equal(t, r_nh, nh)
}

func TestASPathLen(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:999::path_test.go:TestASPathLen(t>>>")
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002, 65003, 65004, 65004, 65004, 65004, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
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
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)
	assert.Equal(10, p.GetAsPathLen())
}

func TestPathPrependAsnToExistingSeqAttr(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1000::path_test.go:TestPathPrependAsnToExistingSeqAttr(t>>>")
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

	p.PrependAsn(65000, 1, false)
	assert.Equal([]uint32{65000, 65001, 65002, 65003, 65004, 65005, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathAttr(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1001::path_test.go:TestPathPrependAsnToNewAsPathAttr(t>>>")
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn}, p.GetAsSeqList())
}

func TestPathPrependAsnToNewAsPathSeq(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1002::path_test.go:TestPathPrependAsnToNewAsPathSeq(t>>>")
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToEmptyAsPathAttr(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1003::path_test.go:TestPathPrependAsnToEmptyAsPathAttr(t>>>")
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)
	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

	asn := uint32(65000)
	p.PrependAsn(asn, 1, false)
	assert.Equal([]uint32{asn, 0, 0, 0}, p.GetAsSeqList())
}

func TestPathPrependAsnToFullPathAttr(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1004::path_test.go:TestPathPrependAsnToFullPathAttr(t>>>")
	assert := assert.New(t)
	origin := bgp.NewPathAttributeOrigin(0)

	asns := make([]uint16, 255)
	for i, _ := range asns {
		asns[i] = 65000 + uint16(i)
	}

	aspathParam := []bgp.AsPathParamInterface{
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SET, []uint16{65001, 65002, 65003, 65004, 65005}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, []uint16{65100, 65101, 65102}),
		bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, []uint16{65100, 65101})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nexthop := bgp.NewPathAttributeNextHop("192.168.50.1")

	pathAttributes := []bgp.PathAttributeInterface{
		origin,
		aspath,
		nexthop,
	}

	nlri := []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "10.10.10.0")}
	bgpmsg := bgp.NewBGPUpdateMessage(nil, pathAttributes, nlri)
	update := bgpmsg.Body.(*bgp.BGPUpdate)
	UpdatePathAttrs4ByteAs(update)
	peer := PathCreatePeer()
	p := NewPath(peer[0], update.NLRI[0], false, update.PathAttributes, time.Now(), false)

	expected := []uint32{65000, 65000}
	for _, v := range asns {
		expected = append(expected, uint32(v))
	}
	p.PrependAsn(65000, 2, false)
	assert.Equal(append(expected, []uint32{0, 0, 0}...), p.GetAsSeqList())
}

func TestGetPathAttrs(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1005::path_test.go:TestGetPathAttrs(t>>>")
	paths := PathCreatePath(PathCreatePeer())
	path0 := paths[0]
	path1 := path0.Clone(false)
	path1.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	path2 := path1.Clone(false)
	path2.setPathAttr(bgp.NewPathAttributeNextHop("192.168.50.1"))
	assert.NotNil(t, path2.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP))
}

func PathCreatePeer() []*PeerInfo { 
   fmt.Print("<<<DEJDEJ id:1006::path_test.go:PathCreatePeer()>>>")
	peerP1 := &PeerInfo{AS: 65000}
	peerP2 := &PeerInfo{AS: 65001}
	peerP3 := &PeerInfo{AS: 65002}
	peerP := []*PeerInfo{peerP1, peerP2, peerP3}
	return peerP
}

func PathCreatePath(peerP []*PeerInfo) []*Path { 
   fmt.Print("<<<DEJDEJ id:1007::path_test.go:PathCreatePath(peerP>>>")
	bgpMsgP1 := updateMsgP1()
	bgpMsgP2 := updateMsgP2()
	bgpMsgP3 := updateMsgP3()
	pathP := make([]*Path, 3)
	for i, msg := range []*bgp.BGPMessage{bgpMsgP1, bgpMsgP2, bgpMsgP3} {
		updateMsgP := msg.Body.(*bgp.BGPUpdate)
		nlriList := updateMsgP.NLRI
		pathAttributes := updateMsgP.PathAttributes
		nlri_info := nlriList[0]
		pathP[i] = NewPath(peerP[i], nlri_info, false, pathAttributes, time.Now(), false)
	}
	return pathP
}

func updateMsgP1() *bgp.BGPMessage { 
   fmt.Print("<<<DEJDEJ id:1008::path_test.go:updateMsgP1()>>>")

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

func updateMsgP2() *bgp.BGPMessage { 
   fmt.Print("<<<DEJDEJ id:1009::path_test.go:updateMsgP2()>>>")

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

func updateMsgP3() *bgp.BGPMessage { 
   fmt.Print("<<<DEJDEJ id:1010::path_test.go:updateMsgP3()>>>")
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

func TestRemovePrivateAS(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1011::path_test.go:TestRemovePrivateAS(t>>>")
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64513, 1, 2})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nlri := bgp.NewIPAddrPrefix(24, "30.30.30.0")
	path := NewPath(nil, nlri, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path.RemovePrivateAS(10, config.REMOVE_PRIVATE_AS_OPTION_ALL)
	list := path.GetAsList()
	assert.Equal(t, len(list), 2)
	assert.Equal(t, list[0], uint32(1))
	assert.Equal(t, list[1], uint32(2))

	path = NewPath(nil, nlri, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path.RemovePrivateAS(10, config.REMOVE_PRIVATE_AS_OPTION_REPLACE)
	list = path.GetAsList()
	assert.Equal(t, len(list), 4)
	assert.Equal(t, list[0], uint32(10))
	assert.Equal(t, list[1], uint32(10))
	assert.Equal(t, list[2], uint32(1))
	assert.Equal(t, list[3], uint32(2))
}

func TestReplaceAS(t *testing.T) { 
   fmt.Print("<<<DEJDEJ id:1012::path_test.go:TestReplaceAS(t>>>")
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, []uint32{64512, 64513, 1, 2})}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	nlri := bgp.NewIPAddrPrefix(24, "30.30.30.0")
	path := NewPath(nil, nlri, false, []bgp.PathAttributeInterface{aspath}, time.Now(), false)
	path = path.ReplaceAS(10, 1)
	list := path.GetAsList()
	assert.Equal(t, len(list), 4)
	assert.Equal(t, list[0], uint32(64512))
	assert.Equal(t, list[1], uint32(64513))
	assert.Equal(t, list[2], uint32(10))
	assert.Equal(t, list[3], uint32(2))
}
