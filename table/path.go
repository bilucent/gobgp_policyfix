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
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	uuid "github.com/satori/go.uuid"

	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
)

const (
	DEFAULT_LOCAL_PREF = 100
)

type Bitmap struct {
	bitmap []uint64
}

func (b *Bitmap) Flag(i uint) { 
   fmt.Print("<<<DEJDEJ id:1282, path.go:Flag>>>")
	b.bitmap[i/64] |= 1 << uint(i%64)
}

func (b *Bitmap) Unflag(i uint) { 
   fmt.Print("<<<DEJDEJ id:1283, path.go:Unflag>>>")
	b.bitmap[i/64] &^= 1 << uint(i%64)
}

func (b *Bitmap) GetFlag(i uint) bool { 
   fmt.Print("<<<DEJDEJ id:1284, path.go:GetFlag>>>")
	return b.bitmap[i/64]&(1<<uint(i%64)) > 0
}

func (b *Bitmap) FindandSetZeroBit() (uint, error) { 
   fmt.Print("<<<DEJDEJ id:1285, path.go:FindandSetZeroBit>>>")
	for i := 0; i < len(b.bitmap); i++ {
		if b.bitmap[i] == math.MaxUint64 {
			continue
		}
		// replace this with TrailingZero64() when gobgp drops go 1.8 support.
		for j := 0; j < 64; j++ {
			v := ^b.bitmap[i]
			if v&(1<<uint64(j)) > 0 {
				r := i*64 + j
				b.Flag(uint(r))
				return uint(r), nil
			}
		}
	}
	return 0, fmt.Errorf("no space")
}

func (b *Bitmap) Expand() { 
   fmt.Print("<<<DEJDEJ id:1286, path.go:Expand>>>")
	old := b.bitmap
	new := make([]uint64, len(old)+1)
	for i := 0; i < len(old); i++ {
		new[i] = old[i]
	}
	b.bitmap = new
}

func NewBitmap(size int) *Bitmap { 
   fmt.Print("<<<DEJDEJ id:1287, path.go:NewBitmap(size>>>")
	b := &Bitmap{}
	if size != 0 {
		b.bitmap = make([]uint64, (size+64-1)/64)
	}
	return b
}

type originInfo struct {
	nlri               bgp.AddrPrefixInterface
	source             *PeerInfo
	timestamp          int64
	validation         *Validation
	key                string
	uuid               uuid.UUID
	noImplicitWithdraw bool
	isFromExternal     bool
	eor                bool
	stale              bool
}

type RpkiValidationReasonType string

const (
	RPKI_VALIDATION_REASON_TYPE_NONE   RpkiValidationReasonType = "none"
	RPKI_VALIDATION_REASON_TYPE_AS     RpkiValidationReasonType = "as"
	RPKI_VALIDATION_REASON_TYPE_LENGTH RpkiValidationReasonType = "length"
)

var RpkiValidationReasonTypeToIntMap = map[RpkiValidationReasonType]int{
	RPKI_VALIDATION_REASON_TYPE_NONE:   0,
	RPKI_VALIDATION_REASON_TYPE_AS:     1,
	RPKI_VALIDATION_REASON_TYPE_LENGTH: 2,
}

func (v RpkiValidationReasonType) ToInt() int { 
   fmt.Print("<<<DEJDEJ id:1288, path.go:ToInt>>>")
	i, ok := RpkiValidationReasonTypeToIntMap[v]
	if !ok {
		return -1
	}
	return i
}

var IntToRpkiValidationReasonTypeMap = map[int]RpkiValidationReasonType{
	0: RPKI_VALIDATION_REASON_TYPE_NONE,
	1: RPKI_VALIDATION_REASON_TYPE_AS,
	2: RPKI_VALIDATION_REASON_TYPE_LENGTH,
}

type Validation struct {
	Status          config.RpkiValidationResultType
	Reason          RpkiValidationReasonType
	Matched         []*ROA
	UnmatchedAs     []*ROA
	UnmatchedLength []*ROA
}

type Path struct {
	info       *originInfo
	IsWithdraw bool
	pathAttrs  []bgp.PathAttributeInterface
	attrsHash  uint32
	reason     BestPathReason
	parent     *Path
	dels       []bgp.BGPAttrType
	filtered   map[string]PolicyDirection
	VrfIds     []uint16
	// For BGP Nexthop Tracking, this field shows if nexthop is invalidated by IGP.
	IsNexthopInvalid bool
}

func NewPath(source *PeerInfo, nlri bgp.AddrPrefixInterface, isWithdraw bool, pattrs []bgp.PathAttributeInterface, timestamp time.Time, noImplicitWithdraw bool) *Path { 
   fmt.Print("<<<DEJDEJ id:1289, path.go:NewPath(source>>>")
	if !isWithdraw && pattrs == nil {
		log.WithFields(log.Fields{
			"Topic": "Table",
			"Key":   nlri.String(),
		}).Error("Need to provide path attributes for non-withdrawn path.")
		return nil
	}

	return &Path{
		info: &originInfo{
			nlri:               nlri,
			source:             source,
			timestamp:          timestamp.Unix(),
			noImplicitWithdraw: noImplicitWithdraw,
		},
		IsWithdraw: isWithdraw,
		pathAttrs:  pattrs,
		filtered:   make(map[string]PolicyDirection),
	}
}

func NewEOR(family bgp.RouteFamily) *Path { 
   fmt.Print("<<<DEJDEJ id:1290, path.go:NewEOR(family>>>")
	afi, safi := bgp.RouteFamilyToAfiSafi(family)
	nlri, _ := bgp.NewPrefixFromRouteFamily(afi, safi)
	return &Path{
		info: &originInfo{
			nlri: nlri,
			eor:  true,
		},
		filtered: make(map[string]PolicyDirection),
	}
}

func (path *Path) IsEOR() bool { 
   fmt.Print("<<<DEJDEJ id:1291, path.go:IsEOR>>>")
	if path.info != nil && path.info.eor {
		return true
	}
	return false
}

func cloneAsPath(asAttr *bgp.PathAttributeAsPath) *bgp.PathAttributeAsPath { 
   fmt.Print("<<<DEJDEJ id:1292, path.go:cloneAsPath(asAttr>>>")
	newASparams := make([]bgp.AsPathParamInterface, len(asAttr.Value))
	for i, param := range asAttr.Value {
		asParam := param.(*bgp.As4PathParam)
		as := make([]uint32, len(asParam.AS))
		copy(as, asParam.AS)
		newASparams[i] = bgp.NewAs4PathParam(asParam.Type, as)
	}
	return bgp.NewPathAttributeAsPath(newASparams)
}

func UpdatePathAttrs(global *config.Global, peer *config.Neighbor, info *PeerInfo, original *Path) *Path { 
   fmt.Print("<<<DEJDEJ id:1293, path.go:UpdatePathAttrs(global>>>")
	if peer.RouteServer.Config.RouteServerClient {
		return original
	}
	path := original.Clone(original.IsWithdraw)

	for _, a := range path.GetPathAttrs() {
		if _, y := bgp.PathAttrFlags[a.GetType()]; !y {
			if a.GetFlags()&bgp.BGP_ATTR_FLAG_TRANSITIVE == 0 {
				path.delPathAttr(a.GetType())
			}
		} else {
			switch a.GetType() {
			case bgp.BGP_ATTR_TYPE_CLUSTER_LIST, bgp.BGP_ATTR_TYPE_ORIGINATOR_ID:
				if !(peer.State.PeerType == config.PEER_TYPE_INTERNAL && peer.RouteReflector.Config.RouteReflectorClient) {
					// send these attributes to only rr clients
					path.delPathAttr(a.GetType())
				}
			}
		}
	}

	localAddress := info.LocalAddress
	nexthop := path.GetNexthop()
	if peer.State.PeerType == config.PEER_TYPE_EXTERNAL {
		// NEXTHOP handling
		if !path.IsLocal() || nexthop.IsUnspecified() {
			path.SetNexthop(localAddress)
		}

		// remove-private-as handling
		path.RemovePrivateAS(peer.Config.LocalAs, peer.State.RemovePrivateAs)

		// AS_PATH handling
		confed := peer.IsConfederationMember(global)
		path.PrependAsn(peer.Config.LocalAs, 1, confed)
		if !confed {
			path.removeConfedAs()
		}

		// MED Handling
		if med := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC); med != nil && !path.IsLocal() {
			path.delPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		}

	} else if peer.State.PeerType == config.PEER_TYPE_INTERNAL {
		// NEXTHOP handling for iBGP
		// if the path generated locally set local address as nexthop.
		// if not, don't modify it.
		// TODO: NEXT-HOP-SELF support
		if path.IsLocal() && nexthop.IsUnspecified() {
			path.SetNexthop(localAddress)
		}

		// AS_PATH handling for iBGP
		// if the path has AS_PATH path attribute, don't modify it.
		// if not, attach *empty* AS_PATH path attribute.
		if nh := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); nh == nil {
			path.PrependAsn(0, 0, false)
		}

		// For iBGP peers we are required to send local-pref attribute
		// for connected or local prefixes.
		// We set default local-pref 100.
		if pref := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF); pref == nil {
			path.setPathAttr(bgp.NewPathAttributeLocalPref(DEFAULT_LOCAL_PREF))
		}

		// RFC4456: BGP Route Reflection
		// 8. Avoiding Routing Information Loops
		info := path.GetSource()
		if peer.RouteReflector.Config.RouteReflectorClient {
			// This attribute will carry the BGP Identifier of the originator of the route in the local AS.
			// A BGP speaker SHOULD NOT create an ORIGINATOR_ID attribute if one already exists.
			//
			// RFC4684 3.2 Intra-AS VPN Route Distribution
			// When advertising RT membership NLRI to a route-reflector client,
			// the Originator attribute shall be set to the router-id of the
			// advertiser, and the Next-hop attribute shall be set of the local
			// address for that session.
			if path.GetRouteFamily() == bgp.RF_RTC_UC {
				path.SetNexthop(localAddress)
				path.setPathAttr(bgp.NewPathAttributeOriginatorId(info.LocalID.String()))
			} else if path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID) == nil {
				if path.IsLocal() {
					path.setPathAttr(bgp.NewPathAttributeOriginatorId(global.Config.RouterId))
				} else {
					path.setPathAttr(bgp.NewPathAttributeOriginatorId(info.ID.String()))
				}
			}
			// When an RR reflects a route, it MUST prepend the local CLUSTER_ID to the CLUSTER_LIST.
			// If the CLUSTER_LIST is empty, it MUST create a new one.
			id := string(peer.RouteReflector.Config.RouteReflectorClusterId)
			if p := path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST); p == nil {
				path.setPathAttr(bgp.NewPathAttributeClusterList([]string{id}))
			} else {
				clusterList := p.(*bgp.PathAttributeClusterList)
				newClusterList := make([]string, 0, len(clusterList.Value))
				for _, ip := range clusterList.Value {
					newClusterList = append(newClusterList, ip.String())
				}
				path.setPathAttr(bgp.NewPathAttributeClusterList(append([]string{id}, newClusterList...)))
			}
		}

	} else {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.State.NeighborAddress,
		}).Warnf("invalid peer type: %d", peer.State.PeerType)
	}
	return path
}

func (path *Path) GetTimestamp() time.Time { 
   fmt.Print("<<<DEJDEJ id:1294, path.go:GetTimestamp>>>")
	return time.Unix(path.OriginInfo().timestamp, 0)
}

func (path *Path) setTimestamp(t time.Time) { 
   fmt.Print("<<<DEJDEJ id:1295, path.go:setTimestamp>>>")
	path.OriginInfo().timestamp = t.Unix()
}

func (path *Path) IsLocal() bool { 
   fmt.Print("<<<DEJDEJ id:1296, path.go:IsLocal>>>")
	return path.GetSource().Address == nil
}

func (path *Path) IsIBGP() bool { 
   fmt.Print("<<<DEJDEJ id:1297, path.go:IsIBGP>>>")
	return path.GetSource().AS == path.GetSource().LocalAS
}

// create new PathAttributes
func (path *Path) Clone(isWithdraw bool) *Path { 
   fmt.Print("<<<DEJDEJ id:1298, path.go:Clone>>>")
	return &Path{
		parent:           path,
		IsWithdraw:       isWithdraw,
		filtered:         make(map[string]PolicyDirection),
		IsNexthopInvalid: path.IsNexthopInvalid,
	}
}

func (path *Path) root() *Path { 
   fmt.Print("<<<DEJDEJ id:1299, path.go:root>>>")
	p := path
	for p.parent != nil {
		p = p.parent
	}
	return p
}

func (path *Path) OriginInfo() *originInfo { 
   fmt.Print("<<<DEJDEJ id:1300, path.go:OriginInfo>>>")
	return path.root().info
}

func (path *Path) NoImplicitWithdraw() bool { 
   fmt.Print("<<<DEJDEJ id:1301, path.go:NoImplicitWithdraw>>>")
	return path.OriginInfo().noImplicitWithdraw
}

func (path *Path) Validation() *Validation { 
   fmt.Print("<<<DEJDEJ id:1302, path.go:Validation>>>")
	return path.OriginInfo().validation
}

func (path *Path) ValidationStatus() config.RpkiValidationResultType { 
   fmt.Print("<<<DEJDEJ id:1303, path.go:ValidationStatus>>>")
	if v := path.OriginInfo().validation; v != nil {
		return v.Status
	} else {
		return config.RPKI_VALIDATION_RESULT_TYPE_NONE
	}
}

func (path *Path) SetValidation(v *Validation) { 
   fmt.Print("<<<DEJDEJ id:1304, path.go:SetValidation>>>")
	path.OriginInfo().validation = v
}

func (path *Path) IsFromExternal() bool { 
   fmt.Print("<<<DEJDEJ id:1305, path.go:IsFromExternal>>>")
	return path.OriginInfo().isFromExternal
}

func (path *Path) SetIsFromExternal(y bool) { 
   fmt.Print("<<<DEJDEJ id:1306, path.go:SetIsFromExternal>>>")
	path.OriginInfo().isFromExternal = y
}

func (path *Path) UUID() uuid.UUID { 
   fmt.Print("<<<DEJDEJ id:1307, path.go:UUID>>>")
	return path.OriginInfo().uuid
}

func (path *Path) SetUUID(id []byte) { 
   fmt.Print("<<<DEJDEJ id:1308, path.go:SetUUID>>>")
	path.OriginInfo().uuid = uuid.FromBytesOrNil(id)
}

func (path *Path) AssignNewUUID() { 
   fmt.Print("<<<DEJDEJ id:1309, path.go:AssignNewUUID>>>")
	path.OriginInfo().uuid, _ = uuid.NewV4()
}

func (path *Path) Filter(id string, reason PolicyDirection) { 
   fmt.Print("<<<DEJDEJ id:1310, path.go:Filter>>>")
	path.filtered[id] = reason
}

func (path *Path) Filtered(id string) PolicyDirection { 
   fmt.Print("<<<DEJDEJ id:1311, path.go:Filtered>>>")
	return path.filtered[id]
}

func (path *Path) GetRouteFamily() bgp.RouteFamily { 
   fmt.Print("<<<DEJDEJ id:1312, path.go:GetRouteFamily>>>")
	return bgp.AfiSafiToRouteFamily(path.OriginInfo().nlri.AFI(), path.OriginInfo().nlri.SAFI())
}

func (path *Path) SetSource(source *PeerInfo) { 
   fmt.Print("<<<DEJDEJ id:1313, path.go:SetSource>>>")
	path.OriginInfo().source = source
}
func (path *Path) GetSource() *PeerInfo { 
   fmt.Print("<<<DEJDEJ id:1314, path.go:GetSource>>>")
	return path.OriginInfo().source
}

func (path *Path) MarkStale(s bool) { 
   fmt.Print("<<<DEJDEJ id:1315, path.go:MarkStale>>>")
	path.OriginInfo().stale = s
}

func (path *Path) IsStale() bool { 
   fmt.Print("<<<DEJDEJ id:1316, path.go:IsStale>>>")
	return path.OriginInfo().stale
}

func (path *Path) IsLLGRStale() bool { 
   fmt.Print("<<<DEJDEJ id:1317, path.go:IsLLGRStale>>>")
	for _, c := range path.GetCommunities() {
		if c == bgp.COMMUNITY_LLGR_STALE {
			return true
		}
	}
	return false
}

func (path *Path) GetSourceAs() uint32 { 
   fmt.Print("<<<DEJDEJ id:1318, path.go:GetSourceAs>>>")
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		asPathParam := attr.(*bgp.PathAttributeAsPath).Value
		if len(asPathParam) == 0 {
			return 0
		}
		asPath := asPathParam[len(asPathParam)-1].(*bgp.As4PathParam)
		if asPath.Num == 0 {
			return 0
		}
		return asPath.AS[asPath.Num-1]
	}
	return 0
}

func (path *Path) GetNexthop() net.IP { 
   fmt.Print("<<<DEJDEJ id:1319, path.go:GetNexthop>>>")
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		return attr.(*bgp.PathAttributeNextHop).Value
	}
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		return attr.(*bgp.PathAttributeMpReachNLRI).Nexthop
	}
	return net.IP{}
}

func (path *Path) SetNexthop(nexthop net.IP) { 
   fmt.Print("<<<DEJDEJ id:1320, path.go:SetNexthop>>>")
	if path.GetRouteFamily() == bgp.RF_IPv4_UC && nexthop.To4() == nil {
		path.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
		mpreach := bgp.NewPathAttributeMpReachNLRI(nexthop.String(), []bgp.AddrPrefixInterface{path.GetNlri()})
		path.setPathAttr(mpreach)
		return
	}
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	if attr != nil {
		path.setPathAttr(bgp.NewPathAttributeNextHop(nexthop.String()))
	}
	attr = path.getPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
	if attr != nil {
		oldNlri := attr.(*bgp.PathAttributeMpReachNLRI)
		path.setPathAttr(bgp.NewPathAttributeMpReachNLRI(nexthop.String(), oldNlri.Value))
	}
}

func (path *Path) GetNlri() bgp.AddrPrefixInterface { 
   fmt.Print("<<<DEJDEJ id:1321, path.go:GetNlri>>>")
	return path.OriginInfo().nlri
}

type PathAttrs []bgp.PathAttributeInterface

func (a PathAttrs) Len() int { 
   fmt.Print("<<<DEJDEJ id:1322, path.go:Len>>>")
	return len(a)
}

func (a PathAttrs) Swap(i, j int) { 
   fmt.Print("<<<DEJDEJ id:1323, path.go:Swap>>>")
	a[i], a[j] = a[j], a[i]
}

func (a PathAttrs) Less(i, j int) bool { 
   fmt.Print("<<<DEJDEJ id:1324, path.go:Less>>>")
	return a[i].GetType() < a[j].GetType()
}

func (path *Path) GetPathAttrs() []bgp.PathAttributeInterface { 
   fmt.Print("<<<DEJDEJ id:1325, path.go:GetPathAttrs>>>")
	deleted := NewBitmap(math.MaxUint8)
	modified := make(map[uint]bgp.PathAttributeInterface)
	p := path
	for {
		for _, t := range p.dels {
			deleted.Flag(uint(t))
		}
		if p.parent == nil {
			list := PathAttrs(make([]bgp.PathAttributeInterface, 0, len(p.pathAttrs)))
			// we assume that the original pathAttrs are
			// in order, that is, other bgp speakers send
			// attributes in order.
			for _, a := range p.pathAttrs {
				typ := uint(a.GetType())
				if m, ok := modified[typ]; ok {
					list = append(list, m)
					delete(modified, typ)
				} else if !deleted.GetFlag(typ) {
					list = append(list, a)
				}
			}
			if len(modified) > 0 {
				// Huh, some attributes were newly
				// added. So we need to sort...
				for _, m := range modified {
					list = append(list, m)
				}
				sort.Sort(list)
			}
			return list
		} else {
			for _, a := range p.pathAttrs {
				typ := uint(a.GetType())
				if _, ok := modified[typ]; !deleted.GetFlag(typ) && !ok {
					modified[typ] = a
				}
			}
		}
		p = p.parent
	}
}

func (path *Path) getPathAttr(typ bgp.BGPAttrType) bgp.PathAttributeInterface { 
   fmt.Print("<<<DEJDEJ id:1326, path.go:getPathAttr>>>")
	p := path
	for {
		for _, t := range p.dels {
			if t == typ {
				return nil
			}
		}
		for _, a := range p.pathAttrs {
			if a.GetType() == typ {
				return a
			}
		}
		if p.parent == nil {
			return nil
		}
		p = p.parent
	}
}

func (path *Path) setPathAttr(a bgp.PathAttributeInterface) { 
   fmt.Print("<<<DEJDEJ id:1327, path.go:setPathAttr>>>")
	if len(path.pathAttrs) == 0 {
		path.pathAttrs = []bgp.PathAttributeInterface{a}
	} else {
		for i, b := range path.pathAttrs {
			if a.GetType() == b.GetType() {
				path.pathAttrs[i] = a
				return
			}
		}
		path.pathAttrs = append(path.pathAttrs, a)
	}
}

func (path *Path) delPathAttr(typ bgp.BGPAttrType) { 
   fmt.Print("<<<DEJDEJ id:1328, path.go:delPathAttr>>>")
	if len(path.dels) == 0 {
		path.dels = []bgp.BGPAttrType{typ}
	} else {
		path.dels = append(path.dels, typ)
	}
}

// return Path's string representation
func (path *Path) String() string { 
   fmt.Print("<<<DEJDEJ id:1329, path.go:String>>>")
	s := bytes.NewBuffer(make([]byte, 0, 64))
	if path.IsEOR() {
		s.WriteString(fmt.Sprintf("{ %s EOR | src: %s }", path.GetRouteFamily(), path.GetSource()))
		return s.String()
	}
	s.WriteString(fmt.Sprintf("{ %s | ", path.getPrefix()))
	s.WriteString(fmt.Sprintf("src: %s", path.GetSource()))
	s.WriteString(fmt.Sprintf(", nh: %s", path.GetNexthop()))
	if path.IsNexthopInvalid {
		s.WriteString(" (not reachable)")
	}
	if path.IsWithdraw {
		s.WriteString(", withdraw")
	}
	s.WriteString(" }")
	return s.String()
}

func (path *Path) getPrefix() string { 
   fmt.Print("<<<DEJDEJ id:1330, path.go:getPrefix>>>")
	if path.OriginInfo().key == "" {
		path.OriginInfo().key = path.GetNlri().String()
	}
	return path.OriginInfo().key
}

func (path *Path) GetAsPath() *bgp.PathAttributeAsPath { 
   fmt.Print("<<<DEJDEJ id:1331, path.go:GetAsPath>>>")
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		return attr.(*bgp.PathAttributeAsPath)
	}
	return nil
}

// GetAsPathLen returns the number of AS_PATH
func (path *Path) GetAsPathLen() int { 
   fmt.Print("<<<DEJDEJ id:1332, path.go:GetAsPathLen>>>")

	var length int = 0
	if aspath := path.GetAsPath(); aspath != nil {
		for _, as := range aspath.Value {
			length += as.ASLen()
		}
	}
	return length
}

func (path *Path) GetAsString() string { 
   fmt.Print("<<<DEJDEJ id:1333, path.go:GetAsString>>>")
	s := bytes.NewBuffer(make([]byte, 0, 64))
	if aspath := path.GetAsPath(); aspath != nil {
		for i, paramIf := range aspath.Value {
			segment := paramIf.(*bgp.As4PathParam)
			if i != 0 {
				s.WriteString(" ")
			}

			sep := " "
			switch segment.Type {
			case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
				s.WriteString("(")
			case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
				s.WriteString("[")
				sep = ","
			case bgp.BGP_ASPATH_ATTR_TYPE_SET:
				s.WriteString("{")
				sep = ","
			}
			for j, as := range segment.AS {
				s.WriteString(fmt.Sprintf("%d", as))
				if j != len(segment.AS)-1 {
					s.WriteString(sep)
				}
			}
			switch segment.Type {
			case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
				s.WriteString(")")
			case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
				s.WriteString("]")
			case bgp.BGP_ASPATH_ATTR_TYPE_SET:
				s.WriteString("}")
			}
		}
	}
	return s.String()
}

func (path *Path) GetAsList() []uint32 { 
   fmt.Print("<<<DEJDEJ id:1334, path.go:GetAsList>>>")
	return path.getAsListofSpecificType(true, true)

}

func (path *Path) GetAsSeqList() []uint32 { 
   fmt.Print("<<<DEJDEJ id:1335, path.go:GetAsSeqList>>>")
	return path.getAsListofSpecificType(true, false)

}

func (path *Path) getAsListofSpecificType(getAsSeq, getAsSet bool) []uint32 { 
   fmt.Print("<<<DEJDEJ id:1336, path.go:getAsListofSpecificType>>>")
	asList := []uint32{}
	if aspath := path.GetAsPath(); aspath != nil {
		for _, paramIf := range aspath.Value {
			segment := paramIf.(*bgp.As4PathParam)
			if getAsSeq && segment.Type == bgp.BGP_ASPATH_ATTR_TYPE_SEQ {
				asList = append(asList, segment.AS...)
				continue
			}
			if getAsSet && segment.Type == bgp.BGP_ASPATH_ATTR_TYPE_SET {
				asList = append(asList, segment.AS...)
			} else {
				asList = append(asList, 0)
			}
		}
	}
	return asList
}

func (path *Path) GetLabelString() string { 
   fmt.Print("<<<DEJDEJ id:1337, path.go:GetLabelString>>>")
	label := ""
	switch n := path.GetNlri().(type) {
	case *bgp.LabeledIPAddrPrefix:
		label = n.Labels.String()
	case *bgp.LabeledIPv6AddrPrefix:
		label = n.Labels.String()
	case *bgp.LabeledVPNIPAddrPrefix:
		label = n.Labels.String()
	case *bgp.LabeledVPNIPv6AddrPrefix:
		label = n.Labels.String()
	case *bgp.EVPNNLRI:
		switch route := n.RouteTypeData.(type) {
		case *bgp.EVPNEthernetAutoDiscoveryRoute:
			label = fmt.Sprintf("[%d]", route.Label)
		case *bgp.EVPNMacIPAdvertisementRoute:
			var l []string
			for _, i := range route.Labels {
				l = append(l, strconv.Itoa(int(i)))
			}
			label = fmt.Sprintf("[%s]", strings.Join(l, ","))
		case *bgp.EVPNIPPrefixRoute:
			label = fmt.Sprintf("[%d]", route.Label)
		}
	}
	return label
}

// PrependAsn prepends AS number.
// This function updates the AS_PATH attribute as follows.
// (If the peer is in the confederation member AS,
//  replace AS_SEQUENCE in the following sentence with AS_CONFED_SEQUENCE.)
//  1) if the first path segment of the AS_PATH is of type
//     AS_SEQUENCE, the local system prepends the specified AS num as
//     the last element of the sequence (put it in the left-most
//     position with respect to the position of  octets in the
//     protocol message) the specified number of times.
//     If the act of prepending will cause an overflow in the AS_PATH
//     segment (i.e.,  more than 255 ASes),
//     it SHOULD prepend a new segment of type AS_SEQUENCE
//     and prepend its own AS number to this new segment.
//
//  2) if the first path segment of the AS_PATH is of other than type
//     AS_SEQUENCE, the local system prepends a new path segment of type
//     AS_SEQUENCE to the AS_PATH, including the specified AS number in
//     that segment.
//
//  3) if the AS_PATH is empty, the local system creates a path
//     segment of type AS_SEQUENCE, places the specified AS number
//     into that segment, and places that segment into the AS_PATH.
func (path *Path) PrependAsn(asn uint32, repeat uint8, confed bool) { 
   fmt.Print("<<<DEJDEJ id:1338, path.go:PrependAsn>>>")
	var segType uint8
	if confed {
		segType = bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ
	} else {
		segType = bgp.BGP_ASPATH_ATTR_TYPE_SEQ
	}

	original := path.GetAsPath()

	asns := make([]uint32, repeat)
	for i, _ := range asns {
		asns[i] = asn
	}

	var asPath *bgp.PathAttributeAsPath
	if original == nil {
		asPath = bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{})
	} else {
		asPath = cloneAsPath(original)
	}

	if len(asPath.Value) > 0 {
		fst := asPath.Value[0].(*bgp.As4PathParam)
		if fst.Type == segType {
			if len(fst.AS)+int(repeat) > 255 {
				repeat = uint8(255 - len(fst.AS))
			}
			fst.AS = append(asns[:int(repeat)], fst.AS...)
			fst.Num += repeat
			asns = asns[int(repeat):]
		}
	}

	if len(asns) > 0 {
		p := bgp.NewAs4PathParam(segType, asns)
		asPath.Value = append([]bgp.AsPathParamInterface{p}, asPath.Value...)
	}
	path.setPathAttr(asPath)
}

func isPrivateAS(as uint32) bool { 
   fmt.Print("<<<DEJDEJ id:1339, path.go:isPrivateAS(as>>>")
	return (64512 <= as && as <= 65534) || (4200000000 <= as && as <= 4294967294)
}

func (path *Path) RemovePrivateAS(localAS uint32, option config.RemovePrivateAsOption) { 
   fmt.Print("<<<DEJDEJ id:1340, path.go:RemovePrivateAS>>>")
	original := path.GetAsPath()
	if original == nil {
		return
	}
	switch option {
	case config.REMOVE_PRIVATE_AS_OPTION_ALL, config.REMOVE_PRIVATE_AS_OPTION_REPLACE:
		newASParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
		for _, param := range original.Value {
			asParam := param.(*bgp.As4PathParam)
			newASParam := make([]uint32, 0, len(asParam.AS))
			for _, as := range asParam.AS {
				if isPrivateAS(as) {
					if option == config.REMOVE_PRIVATE_AS_OPTION_REPLACE {
						newASParam = append(newASParam, localAS)
					}
				} else {
					newASParam = append(newASParam, as)
				}
			}
			if len(newASParam) > 0 {
				newASParams = append(newASParams, bgp.NewAs4PathParam(asParam.Type, newASParam))
			}
		}
		path.setPathAttr(bgp.NewPathAttributeAsPath(newASParams))
	}
	return
}

func (path *Path) removeConfedAs() { 
   fmt.Print("<<<DEJDEJ id:1341, path.go:removeConfedAs>>>")
	original := path.GetAsPath()
	if original == nil {
		return
	}
	newAsParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
	for _, v := range original.Value {
		p := v.(*bgp.As4PathParam)
		if p.Type == bgp.BGP_ASPATH_ATTR_TYPE_SEQ || p.Type == bgp.BGP_ASPATH_ATTR_TYPE_SET {
			newAsParams = append(newAsParams, p)
		}
	}
	path.setPathAttr(bgp.NewPathAttributeAsPath(newAsParams))
}

func (path *Path) ReplaceAS(localAS, peerAS uint32) *Path { 
   fmt.Print("<<<DEJDEJ id:1342, path.go:ReplaceAS>>>")
	original := path.GetAsPath()
	if original == nil {
		return path
	}
	newASParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
	changed := false
	for _, param := range original.Value {
		asParam := param.(*bgp.As4PathParam)
		newASParam := make([]uint32, 0, len(asParam.AS))
		for _, as := range asParam.AS {
			if as == peerAS {
				as = localAS
				changed = true
			}
			newASParam = append(newASParam, as)
		}
		newASParams = append(newASParams, bgp.NewAs4PathParam(asParam.Type, newASParam))
	}
	if changed {
		path = path.Clone(path.IsWithdraw)
		path.setPathAttr(bgp.NewPathAttributeAsPath(newASParams))
	}
	return path
}

func (path *Path) GetCommunities() []uint32 { 
   fmt.Print("<<<DEJDEJ id:1343, path.go:GetCommunities>>>")
	communityList := []uint32{}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES); attr != nil {
		communities := attr.(*bgp.PathAttributeCommunities)
		communityList = append(communityList, communities.Value...)
	}
	return communityList
}

// SetCommunities adds or replaces communities with new ones.
// If the length of communities is 0 and doReplace is true, it clears communities.
func (path *Path) SetCommunities(communities []uint32, doReplace bool) { 
   fmt.Print("<<<DEJDEJ id:1344, path.go:SetCommunities>>>")

	if len(communities) == 0 && doReplace {
		// clear communities
		path.delPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
		return
	}

	newList := make([]uint32, 0)
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if attr != nil {
		c := attr.(*bgp.PathAttributeCommunities)
		if doReplace {
			newList = append(newList, communities...)
		} else {
			newList = append(newList, c.Value...)
			newList = append(newList, communities...)
		}
	} else {
		newList = append(newList, communities...)
	}
	path.setPathAttr(bgp.NewPathAttributeCommunities(newList))

}

// RemoveCommunities removes specific communities.
// If the length of communities is 0, it does nothing.
// If all communities are removed, it removes Communities path attribute itself.
func (path *Path) RemoveCommunities(communities []uint32) int { 
   fmt.Print("<<<DEJDEJ id:1345, path.go:RemoveCommunities>>>")

	if len(communities) == 0 {
		// do nothing
		return 0
	}

	find := func(val uint32) bool {
		for _, com := range communities {
			if com == val {
				return true
			}
		}
		return false
	}

	count := 0
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if attr != nil {
		newList := make([]uint32, 0)
		c := attr.(*bgp.PathAttributeCommunities)

		for _, value := range c.Value {
			if find(value) {
				count += 1
			} else {
				newList = append(newList, value)
			}
		}

		if len(newList) != 0 {
			path.setPathAttr(bgp.NewPathAttributeCommunities(newList))
		} else {
			path.delPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
		}
	}
	return count
}

func (path *Path) GetExtCommunities() []bgp.ExtendedCommunityInterface { 
   fmt.Print("<<<DEJDEJ id:1346, path.go:GetExtCommunities>>>")
	eCommunityList := make([]bgp.ExtendedCommunityInterface, 0)
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES); attr != nil {
		eCommunities := attr.(*bgp.PathAttributeExtendedCommunities).Value
		for _, eCommunity := range eCommunities {
			eCommunityList = append(eCommunityList, eCommunity)
		}
	}
	return eCommunityList
}

func (path *Path) SetExtCommunities(exts []bgp.ExtendedCommunityInterface, doReplace bool) { 
   fmt.Print("<<<DEJDEJ id:1347, path.go:SetExtCommunities>>>")
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
	if attr != nil {
		l := attr.(*bgp.PathAttributeExtendedCommunities).Value
		if doReplace {
			l = exts
		} else {
			l = append(l, exts...)
		}
		path.setPathAttr(bgp.NewPathAttributeExtendedCommunities(l))
	} else {
		path.setPathAttr(bgp.NewPathAttributeExtendedCommunities(exts))
	}
}

func (path *Path) GetLargeCommunities() []*bgp.LargeCommunity { 
   fmt.Print("<<<DEJDEJ id:1348, path.go:GetLargeCommunities>>>")
	if a := path.getPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY); a != nil {
		v := a.(*bgp.PathAttributeLargeCommunities).Values
		ret := make([]*bgp.LargeCommunity, 0, len(v))
		for _, c := range v {
			ret = append(ret, c)
		}
		return ret
	}
	return nil
}

func (path *Path) SetLargeCommunities(cs []*bgp.LargeCommunity, doReplace bool) { 
   fmt.Print("<<<DEJDEJ id:1349, path.go:SetLargeCommunities>>>")
	a := path.getPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY)
	if a == nil || doReplace {
		path.setPathAttr(bgp.NewPathAttributeLargeCommunities(cs))
	} else {
		l := a.(*bgp.PathAttributeLargeCommunities).Values
		path.setPathAttr(bgp.NewPathAttributeLargeCommunities(append(l, cs...)))
	}
}

func (path *Path) GetMed() (uint32, error) { 
   fmt.Print("<<<DEJDEJ id:1350, path.go:GetMed>>>")
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	if attr == nil {
		return 0, fmt.Errorf("no med path attr")
	}
	return attr.(*bgp.PathAttributeMultiExitDisc).Value, nil
}

// SetMed replace, add or subtraction med with new ones.
func (path *Path) SetMed(med int64, doReplace bool) error { 
   fmt.Print("<<<DEJDEJ id:1351, path.go:SetMed>>>")

	parseMed := func(orgMed uint32, med int64, doReplace bool) (*bgp.PathAttributeMultiExitDisc, error) {
		newMed := &bgp.PathAttributeMultiExitDisc{}
		if doReplace {
			newMed = bgp.NewPathAttributeMultiExitDisc(uint32(med))
		} else {
			if int64(orgMed)+med < 0 {
				return nil, fmt.Errorf("med value invalid. it's underflow threshold.")
			} else if int64(orgMed)+med > int64(math.MaxUint32) {
				return nil, fmt.Errorf("med value invalid. it's overflow threshold.")
			}
			newMed = bgp.NewPathAttributeMultiExitDisc(uint32(int64(orgMed) + med))
		}
		return newMed, nil
	}

	m := uint32(0)
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC); attr != nil {
		m = attr.(*bgp.PathAttributeMultiExitDisc).Value
	}
	newMed, err := parseMed(m, med, doReplace)
	if err != nil {
		return err
	}
	path.setPathAttr(newMed)
	return nil
}

func (path *Path) RemoveLocalPref() { 
   fmt.Print("<<<DEJDEJ id:1352, path.go:RemoveLocalPref>>>")
	if path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF) != nil {
		path.delPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	}
}

func (path *Path) GetOriginatorID() net.IP { 
   fmt.Print("<<<DEJDEJ id:1353, path.go:GetOriginatorID>>>")
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID); attr != nil {
		return attr.(*bgp.PathAttributeOriginatorId).Value
	}
	return nil
}

func (path *Path) GetClusterList() []net.IP { 
   fmt.Print("<<<DEJDEJ id:1354, path.go:GetClusterList>>>")
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST); attr != nil {
		return attr.(*bgp.PathAttributeClusterList).Value
	}
	return nil
}

func (path *Path) GetOrigin() (uint8, error) { 
   fmt.Print("<<<DEJDEJ id:1355, path.go:GetOrigin>>>")
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN); attr != nil {
		return attr.(*bgp.PathAttributeOrigin).Value, nil
	}
	return 0, fmt.Errorf("no origin path attr")
}

func (path *Path) GetLocalPref() (uint32, error) { 
   fmt.Print("<<<DEJDEJ id:1356, path.go:GetLocalPref>>>")
	lp := uint32(DEFAULT_LOCAL_PREF)
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	if attr != nil {
		lp = attr.(*bgp.PathAttributeLocalPref).Value
	}
	return lp, nil
}

func (lhs *Path) Equal(rhs *Path) bool { 
   fmt.Print("<<<DEJDEJ id:1357, path.go:Equal>>>")
	if rhs == nil {
		return false
	}

	if lhs.GetSource() != rhs.GetSource() {
		return false
	}

	pattrs := func(arg []bgp.PathAttributeInterface) []byte {
		ret := make([]byte, 0)
		for _, a := range arg {
			aa, _ := a.Serialize()
			ret = append(ret, aa...)
		}
		return ret
	}
	return bytes.Equal(pattrs(lhs.GetPathAttrs()), pattrs(rhs.GetPathAttrs()))
}

func (path *Path) MarshalJSON() ([]byte, error) { 
   fmt.Print("<<<DEJDEJ id:1358, path.go:MarshalJSON>>>")
	return json.Marshal(struct {
		Nlri       bgp.AddrPrefixInterface      `json:"nlri"`
		PathAttrs  []bgp.PathAttributeInterface `json:"attrs"`
		Age        int64                        `json:"age"`
		Withdrawal bool                         `json:"withdrawal,omitempty"`
		Validation string                       `json:"validation,omitempty"`
		SourceID   net.IP                       `json:"source-id,omitempty"`
		NeighborIP net.IP                       `json:"neighbor-ip,omitempty"`
		Stale      bool                         `json:"stale,omitempty"`
		Filtered   bool                         `json:"filtered,omitempty"`
		UUID       string                       `json:"uuid,omitempty"`
		ID         uint32                       `json:"id,omitempty"`
	}{
		Nlri:       path.GetNlri(),
		PathAttrs:  path.GetPathAttrs(),
		Age:        path.GetTimestamp().Unix(),
		Withdrawal: path.IsWithdraw,
		Validation: string(path.ValidationStatus()),
		SourceID:   path.GetSource().ID,
		NeighborIP: path.GetSource().Address,
		Stale:      path.IsStale(),
		Filtered:   path.Filtered("") > POLICY_DIRECTION_NONE,
		UUID:       path.UUID().String(),
		ID:         path.GetNlri().PathIdentifier(),
	})
}

func (lhs *Path) Compare(rhs *Path) int { 
   fmt.Print("<<<DEJDEJ id:1359, path.go:Compare>>>")
	if lhs.IsLocal() && !rhs.IsLocal() {
		return 1
	} else if !lhs.IsLocal() && rhs.IsLocal() {
		return -1
	}

	if !lhs.IsIBGP() && rhs.IsIBGP() {
		return 1
	} else if lhs.IsIBGP() && !rhs.IsIBGP() {
		return -1
	}

	lp1, _ := lhs.GetLocalPref()
	lp2, _ := rhs.GetLocalPref()
	if lp1 != lp2 {
		return int(lp1 - lp2)
	}

	l1 := lhs.GetAsPathLen()
	l2 := rhs.GetAsPathLen()
	if l1 != l2 {
		return int(l2 - l1)
	}

	o1, _ := lhs.GetOrigin()
	o2, _ := rhs.GetOrigin()
	if o1 != o2 {
		return int(o2 - o1)
	}

	m1, _ := lhs.GetMed()
	m2, _ := rhs.GetMed()
	return int(m2 - m1)
}

func (v *Vrf) ToGlobalPath(path *Path) error { 
   fmt.Print("<<<DEJDEJ id:1360, path.go:ToGlobalPath>>>")
	nlri := path.GetNlri()
	switch rf := path.GetRouteFamily(); rf {
	case bgp.RF_IPv4_UC:
		n := nlri.(*bgp.IPAddrPrefix)
		path.OriginInfo().nlri = bgp.NewLabeledVPNIPAddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(0), v.Rd)
	case bgp.RF_IPv6_UC:
		n := nlri.(*bgp.IPv6AddrPrefix)
		path.OriginInfo().nlri = bgp.NewLabeledVPNIPv6AddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(0), v.Rd)
	case bgp.RF_EVPN:
		n := nlri.(*bgp.EVPNNLRI)
		switch n.RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute).RD = v.Rd
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute).RD = v.Rd
		}
	default:
		return fmt.Errorf("unsupported route family for vrf: %s", rf)
	}
	path.SetExtCommunities(v.ExportRt, false)
	return nil
}

func (p *Path) ToGlobal(vrf *Vrf) *Path { 
   fmt.Print("<<<DEJDEJ id:1361, path.go:ToGlobal>>>")
	nlri := p.GetNlri()
	nh := p.GetNexthop()
	switch rf := p.GetRouteFamily(); rf {
	case bgp.RF_IPv4_UC:
		n := nlri.(*bgp.IPAddrPrefix)
		nlri = bgp.NewLabeledVPNIPAddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(0), vrf.Rd)
	case bgp.RF_IPv6_UC:
		n := nlri.(*bgp.IPv6AddrPrefix)
		nlri = bgp.NewLabeledVPNIPv6AddrPrefix(n.Length, n.Prefix.String(), *bgp.NewMPLSLabelStack(0), vrf.Rd)
	case bgp.RF_EVPN:
		n := nlri.(*bgp.EVPNNLRI)
		switch n.RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			old := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
			new := &bgp.EVPNMacIPAdvertisementRoute{
				RD:               vrf.Rd,
				ESI:              old.ESI,
				ETag:             old.ETag,
				MacAddressLength: old.MacAddressLength,
				MacAddress:       old.MacAddress,
				IPAddressLength:  old.IPAddressLength,
				IPAddress:        old.IPAddress,
				Labels:           old.Labels,
			}
			nlri = bgp.NewEVPNNLRI(n.RouteType, n.Length, new)
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			old := n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
			new := &bgp.EVPNMulticastEthernetTagRoute{
				RD:              vrf.Rd,
				ETag:            old.ETag,
				IPAddressLength: old.IPAddressLength,
				IPAddress:       old.IPAddress,
			}
			nlri = bgp.NewEVPNNLRI(n.RouteType, n.Length, new)
		}
	default:
		return p
	}
	path := NewPath(p.OriginInfo().source, nlri, p.IsWithdraw, p.GetPathAttrs(), p.GetTimestamp(), false)
	path.SetExtCommunities(vrf.ExportRt, false)
	path.delPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP)
	path.setPathAttr(bgp.NewPathAttributeMpReachNLRI(nh.String(), []bgp.AddrPrefixInterface{nlri}))
	path.IsNexthopInvalid = p.IsNexthopInvalid
	return path
}

func (p *Path) ToLocal() *Path { 
   fmt.Print("<<<DEJDEJ id:1362, path.go:ToLocal>>>")
	nlri := p.GetNlri()
	f := p.GetRouteFamily()
	switch f {
	case bgp.RF_IPv4_VPN:
		n := nlri.(*bgp.LabeledVPNIPAddrPrefix)
		_, c, _ := net.ParseCIDR(n.IPPrefix())
		ones, _ := c.Mask.Size()
		nlri = bgp.NewIPAddrPrefix(uint8(ones), c.IP.String())
	case bgp.RF_IPv6_VPN:
		n := nlri.(*bgp.LabeledVPNIPv6AddrPrefix)
		_, c, _ := net.ParseCIDR(n.IPPrefix())
		ones, _ := c.Mask.Size()
		nlri = bgp.NewIPv6AddrPrefix(uint8(ones), c.IP.String())
	default:
		return p
	}
	path := NewPath(p.OriginInfo().source, nlri, p.IsWithdraw, p.GetPathAttrs(), p.GetTimestamp(), false)
	path.delPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)

	if f == bgp.RF_IPv4_VPN {
		nh := path.GetNexthop()
		path.delPathAttr(bgp.BGP_ATTR_TYPE_MP_REACH_NLRI)
		path.setPathAttr(bgp.NewPathAttributeNextHop(nh.String()))
	}
	path.IsNexthopInvalid = p.IsNexthopInvalid
	return path
}

func (p *Path) SetHash(v uint32) { 
   fmt.Print("<<<DEJDEJ id:1363, path.go:SetHash>>>")
	p.attrsHash = v
}

func (p *Path) GetHash() uint32 { 
   fmt.Print("<<<DEJDEJ id:1364, path.go:GetHash>>>")
	return p.attrsHash
}
