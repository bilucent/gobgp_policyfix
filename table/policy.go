// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
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
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	radix "github.com/armon/go-radix"

	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
)

type PolicyOptions struct {
	Info *PeerInfo
}

type DefinedType int

const (
	DEFINED_TYPE_PREFIX DefinedType = iota
	DEFINED_TYPE_NEIGHBOR
	DEFINED_TYPE_TAG
	DEFINED_TYPE_AS_PATH
	DEFINED_TYPE_COMMUNITY
	DEFINED_TYPE_EXT_COMMUNITY
	DEFINED_TYPE_LARGE_COMMUNITY
)

type RouteType int

const (
	ROUTE_TYPE_NONE RouteType = iota
	ROUTE_TYPE_ACCEPT
	ROUTE_TYPE_REJECT
)

func (t RouteType) String() string {
   fmt.Printf("DEJDEJ id:",3051)
	switch t {
	case ROUTE_TYPE_NONE:
		return "continue"
	case ROUTE_TYPE_ACCEPT:
		return "accept"
	case ROUTE_TYPE_REJECT:
		return "reject"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

type PolicyDirection int

const (
	POLICY_DIRECTION_NONE PolicyDirection = iota
	POLICY_DIRECTION_IN
	POLICY_DIRECTION_IMPORT
	POLICY_DIRECTION_EXPORT
)

func (d PolicyDirection) String() string {
   fmt.Printf("DEJDEJ id:",3052)
	switch d {
	case POLICY_DIRECTION_IN:
		return "in"
	case POLICY_DIRECTION_IMPORT:
		return "import"
	case POLICY_DIRECTION_EXPORT:
		return "export"
	}
	return fmt.Sprintf("unknown(%d)", d)
}

type MatchOption int

const (
	MATCH_OPTION_ANY MatchOption = iota
	MATCH_OPTION_ALL
	MATCH_OPTION_INVERT
)

func (o MatchOption) String() string {
   fmt.Printf("DEJDEJ id:",3053)
	switch o {
	case MATCH_OPTION_ANY:
		return "any"
	case MATCH_OPTION_ALL:
		return "all"
	case MATCH_OPTION_INVERT:
		return "invert"
	default:
		return fmt.Sprintf("MatchOption(%d)", o)
	}
}

func (o MatchOption) ConvertToMatchSetOptionsRestrictedType() config.MatchSetOptionsRestrictedType {
   fmt.Printf("DEJDEJ id:",3054)
	switch o {
	case MATCH_OPTION_ANY:
		return config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	case MATCH_OPTION_INVERT:
		return config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
	}
	return "unknown"
}

type MedActionType int

const (
	MED_ACTION_MOD MedActionType = iota
	MED_ACTION_REPLACE
)

var CommunityOptionNameMap = map[config.BgpSetCommunityOptionType]string{
	config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:     "add",
	config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:  "remove",
	config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE: "replace",
}

var CommunityOptionValueMap = map[string]config.BgpSetCommunityOptionType{
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD]:     config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD,
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE]:  config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE,
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE]: config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE,
}

type ConditionType int

const (
	CONDITION_PREFIX ConditionType = iota
	CONDITION_NEIGHBOR
	CONDITION_AS_PATH
	CONDITION_COMMUNITY
	CONDITION_EXT_COMMUNITY
	CONDITION_AS_PATH_LENGTH
	CONDITION_RPKI
	CONDITION_ROUTE_TYPE
	CONDITION_LARGE_COMMUNITY
)

type ActionType int

const (
	ACTION_ROUTING ActionType = iota
	ACTION_COMMUNITY
	ACTION_EXT_COMMUNITY
	ACTION_MED
	ACTION_AS_PATH_PREPEND
	ACTION_NEXTHOP
	ACTION_LOCAL_PREF
	ACTION_LARGE_COMMUNITY
)

func NewMatchOption(c interface{}) (MatchOption, error) {
   fmt.Printf("DEJDEJ id:",3055)
	switch t := c.(type) {
	case config.MatchSetOptionsType:
		t = t.DefaultAsNeeded()
		switch t {
		case config.MATCH_SET_OPTIONS_TYPE_ANY:
			return MATCH_OPTION_ANY, nil
		case config.MATCH_SET_OPTIONS_TYPE_ALL:
			return MATCH_OPTION_ALL, nil
		case config.MATCH_SET_OPTIONS_TYPE_INVERT:
			return MATCH_OPTION_INVERT, nil
		}
	case config.MatchSetOptionsRestrictedType:
		t = t.DefaultAsNeeded()
		switch t {
		case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY:
			return MATCH_OPTION_ANY, nil
		case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT:
			return MATCH_OPTION_INVERT, nil
		}
	}
	return MATCH_OPTION_ANY, fmt.Errorf("invalid argument to create match option: %v", c)
}

type AttributeComparison int

const (
	// "== comparison"
	ATTRIBUTE_EQ AttributeComparison = iota
	// ">= comparison"
	ATTRIBUTE_GE
	// "<= comparison"
	ATTRIBUTE_LE
)

func (c AttributeComparison) String() string {
   fmt.Printf("DEJDEJ id:",3056)
	switch c {
	case ATTRIBUTE_EQ:
		return "="
	case ATTRIBUTE_GE:
		return ">="
	case ATTRIBUTE_LE:
		return "<="
	}
	return "?"
}

const (
	ASPATH_REGEXP_MAGIC = "(^|[,{}() ]|$)"
)

type DefinedSet interface {
	Type() DefinedType
	Name() string
	Append(DefinedSet) error
	Remove(DefinedSet) error
	Replace(DefinedSet) error
	String() string
	List() []string
}

type DefinedSetMap map[DefinedType]map[string]DefinedSet

type DefinedSetList []DefinedSet

func (l DefinedSetList) Len() int {
   fmt.Printf("DEJDEJ id:",3057)
	return len(l)
}

func (l DefinedSetList) Swap(i, j int) {
   fmt.Printf("DEJDEJ id:",3058)
	l[i], l[j] = l[j], l[i]
}

func (l DefinedSetList) Less(i, j int) bool {
   fmt.Printf("DEJDEJ id:",3059)
	if l[i].Type() != l[j].Type() {
		return l[i].Type() < l[j].Type()
	}
	return l[i].Name() < l[j].Name()
}

type Prefix struct {
	Prefix             *net.IPNet
	AddressFamily      bgp.RouteFamily
	MasklengthRangeMax uint8
	MasklengthRangeMin uint8
}

func (p *Prefix) Match(path *Path) bool {
   fmt.Printf("DEJDEJ id:",3060)
	rf := path.GetRouteFamily()
	if rf != p.AddressFamily {
		return false
	}

	var pAddr net.IP
	var pMasklen uint8
	switch rf {
	case bgp.RF_IPv4_UC:
		pAddr = path.GetNlri().(*bgp.IPAddrPrefix).Prefix
		pMasklen = path.GetNlri().(*bgp.IPAddrPrefix).Length
	case bgp.RF_IPv6_UC:
		pAddr = path.GetNlri().(*bgp.IPv6AddrPrefix).Prefix
		pMasklen = path.GetNlri().(*bgp.IPv6AddrPrefix).Length
	default:
		return false
	}

	return (p.MasklengthRangeMin <= pMasklen && pMasklen <= p.MasklengthRangeMax) && p.Prefix.Contains(pAddr)
}

func (lhs *Prefix) Equal(rhs *Prefix) bool {
   fmt.Printf("DEJDEJ id:",3061)
	if lhs == rhs {
		return true
	}
	if rhs == nil {
		return false
	}
	return lhs.Prefix.String() == rhs.Prefix.String() && lhs.MasklengthRangeMin == rhs.MasklengthRangeMin && lhs.MasklengthRangeMax == rhs.MasklengthRangeMax
}

func (p *Prefix) PrefixString() string {
   fmt.Printf("DEJDEJ id:",3062)
	isZeros := func(p net.IP) bool {
		for i := 0; i < len(p); i++ {
			if p[i] != 0 {
				return false
			}
		}
		return true
	}

	ip := p.Prefix.IP
	if p.AddressFamily == bgp.RF_IPv6_UC && isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff {
		m, _ := p.Prefix.Mask.Size()
		return fmt.Sprintf("::FFFF:%s/%d", ip.To16(), m)
	}
	return p.Prefix.String()
}

func NewPrefix(c config.Prefix) (*Prefix, error) {
   fmt.Printf("DEJDEJ id:",3063)
	_, prefix, err := net.ParseCIDR(c.IpPrefix)
	if err != nil {
		return nil, err
	}

	rf := bgp.RF_IPv4_UC
	if strings.Contains(c.IpPrefix, ":") {
		rf = bgp.RF_IPv6_UC
	}
	p := &Prefix{
		Prefix:        prefix,
		AddressFamily: rf,
	}
	maskRange := c.MasklengthRange
	if maskRange == "" {
		l, _ := prefix.Mask.Size()
		maskLength := uint8(l)
		p.MasklengthRangeMax = maskLength
		p.MasklengthRangeMin = maskLength
	} else {
		exp := regexp.MustCompile("(\\d+)\\.\\.(\\d+)")
		elems := exp.FindStringSubmatch(maskRange)
		if len(elems) != 3 {
			log.WithFields(log.Fields{
				"Topic":           "Policy",
				"Type":            "Prefix",
				"MaskRangeFormat": maskRange,
			}).Warn("mask length range format is invalid.")
			return nil, fmt.Errorf("mask length range format is invalid")
		}
		// we've already checked the range is sane by regexp
		min, _ := strconv.ParseUint(elems[1], 10, 8)
		max, _ := strconv.ParseUint(elems[2], 10, 8)
		p.MasklengthRangeMin = uint8(min)
		p.MasklengthRangeMax = uint8(max)
	}
	return p, nil
}

type PrefixSet struct {
	name   string
	tree   *radix.Tree
	family bgp.RouteFamily
}

func (s *PrefixSet) Name() string {
   fmt.Printf("DEJDEJ id:",3064)
	return s.name
}

func (s *PrefixSet) Type() DefinedType {
   fmt.Printf("DEJDEJ id:",3065)
	return DEFINED_TYPE_PREFIX
}

func (lhs *PrefixSet) Append(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3066)
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	// if either is empty, family can be ignored.
	if lhs.tree.Len() != 0 && rhs.tree.Len() != 0 {
		_, w, _ := lhs.tree.Minimum()
		l := w.([]*Prefix)
		_, v, _ := rhs.tree.Minimum()
		r := v.([]*Prefix)
		if l[0].AddressFamily != r[0].AddressFamily {
			return fmt.Errorf("can't append different family")
		}
	}
	rhs.tree.Walk(func(key string, v interface{}) bool {
		w, ok := lhs.tree.Get(key)
		if ok {
			r := v.([]*Prefix)
			l := w.([]*Prefix)
			lhs.tree.Insert(key, append(l, r...))
		} else {
			lhs.tree.Insert(key, v)
		}
		return false
	})
	_, w, _ := lhs.tree.Minimum()
	lhs.family = w.([]*Prefix)[0].AddressFamily
	return nil
}

func (lhs *PrefixSet) Remove(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3067)
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	rhs.tree.Walk(func(key string, v interface{}) bool {
		w, ok := lhs.tree.Get(key)
		if !ok {
			return false
		}
		r := v.([]*Prefix)
		l := w.([]*Prefix)
		new := make([]*Prefix, 0, len(l))
		for _, lp := range l {
			delete := false
			for _, rp := range r {
				if lp.Equal(rp) {
					delete = true
					break
				}
			}
			if !delete {
				new = append(new, lp)
			}
		}
		if len(new) == 0 {
			lhs.tree.Delete(key)
		} else {
			lhs.tree.Insert(key, new)
		}
		return false
	})
	return nil
}

func (lhs *PrefixSet) Replace(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3068)
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.tree = rhs.tree
	lhs.family = rhs.family
	return nil
}

func (s *PrefixSet) List() []string {
   fmt.Printf("DEJDEJ id:",3069)
	var list []string
	s.tree.Walk(func(s string, v interface{}) bool {
		ps := v.([]*Prefix)
		for _, p := range ps {
			list = append(list, fmt.Sprintf("%s %d..%d", p.PrefixString(), p.MasklengthRangeMin, p.MasklengthRangeMax))
		}
		return false
	})
	return list
}

func (s *PrefixSet) ToConfig() *config.PrefixSet {
   fmt.Printf("DEJDEJ id:",3070)
	list := make([]config.Prefix, 0, s.tree.Len())
	s.tree.Walk(func(s string, v interface{}) bool {
		ps := v.([]*Prefix)
		for _, p := range ps {
			list = append(list, config.Prefix{IpPrefix: p.PrefixString(), MasklengthRange: fmt.Sprintf("%d..%d", p.MasklengthRangeMin, p.MasklengthRangeMax)})
		}
		return false
	})
	return &config.PrefixSet{
		PrefixSetName: s.name,
		PrefixList:    list,
	}
}

func (s *PrefixSet) String() string {
   fmt.Printf("DEJDEJ id:",3071)
	return strings.Join(s.List(), "\n")
}

func (s *PrefixSet) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3072)
	return json.Marshal(s.ToConfig())
}

func NewPrefixSetFromApiStruct(name string, prefixes []*Prefix) (*PrefixSet, error) {
   fmt.Printf("DEJDEJ id:",3073)
	if name == "" {
		return nil, fmt.Errorf("empty prefix set name")
	}
	tree := radix.New()
	var family bgp.RouteFamily
	for i, x := range prefixes {
		if i == 0 {
			family = x.AddressFamily
		} else if family != x.AddressFamily {
			return nil, fmt.Errorf("multiple families")
		}
		key := CidrToRadixkey(x.Prefix.String())
		d, ok := tree.Get(key)
		if ok {
			ps := d.([]*Prefix)
			tree.Insert(key, append(ps, x))
		} else {
			tree.Insert(key, []*Prefix{x})
		}
	}
	return &PrefixSet{
		name:   name,
		tree:   tree,
		family: family,
	}, nil
}

func NewPrefixSet(c config.PrefixSet) (*PrefixSet, error) {
   fmt.Printf("DEJDEJ id:",3074)
	name := c.PrefixSetName
	if name == "" {
		if len(c.PrefixList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty prefix set name")
	}
	tree := radix.New()
	var family bgp.RouteFamily
	for i, x := range c.PrefixList {
		y, err := NewPrefix(x)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			family = y.AddressFamily
		} else if family != y.AddressFamily {
			return nil, fmt.Errorf("multiple families")
		}
		key := CidrToRadixkey(y.Prefix.String())
		d, ok := tree.Get(key)
		if ok {
			ps := d.([]*Prefix)
			tree.Insert(key, append(ps, y))
		} else {
			tree.Insert(key, []*Prefix{y})
		}
	}
	return &PrefixSet{
		name:   name,
		tree:   tree,
		family: family,
	}, nil
}

type NeighborSet struct {
	name string
	list []net.IPNet
}

func (s *NeighborSet) Name() string {
   fmt.Printf("DEJDEJ id:",3075)
	return s.name
}

func (s *NeighborSet) Type() DefinedType {
   fmt.Printf("DEJDEJ id:",3076)
	return DEFINED_TYPE_NEIGHBOR
}

func (lhs *NeighborSet) Append(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3077)
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = append(lhs.list, rhs.list...)
	return nil
}

func (lhs *NeighborSet) Remove(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3078)
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	ps := make([]net.IPNet, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range rhs.list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			ps = append(ps, x)
		}
	}
	lhs.list = ps
	return nil
}

func (lhs *NeighborSet) Replace(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3079)
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	return nil
}

func (s *NeighborSet) List() []string {
   fmt.Printf("DEJDEJ id:",3080)
	list := make([]string, 0, len(s.list))
	for _, n := range s.list {
		list = append(list, n.String())
	}
	return list
}

func (s *NeighborSet) ToConfig() *config.NeighborSet {
   fmt.Printf("DEJDEJ id:",3081)
	return &config.NeighborSet{
		NeighborSetName:  s.name,
		NeighborInfoList: s.List(),
	}
}

func (s *NeighborSet) String() string {
   fmt.Printf("DEJDEJ id:",3082)
	return strings.Join(s.List(), "\n")
}

func (s *NeighborSet) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3083)
	return json.Marshal(s.ToConfig())
}

func NewNeighborSetFromApiStruct(name string, list []net.IPNet) (*NeighborSet, error) {
   fmt.Printf("DEJDEJ id:",3084)
	return &NeighborSet{
		name: name,
		list: list,
	}, nil
}

func NewNeighborSet(c config.NeighborSet) (*NeighborSet, error) {
   fmt.Printf("DEJDEJ id:",3085)
	name := c.NeighborSetName
	if name == "" {
		if len(c.NeighborInfoList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty neighbor set name")
	}
	list := make([]net.IPNet, 0, len(c.NeighborInfoList))
	for _, x := range c.NeighborInfoList {
		_, cidr, err := net.ParseCIDR(x)
		if err != nil {
			addr := net.ParseIP(x)
			if addr == nil {
				return nil, fmt.Errorf("invalid address or prefix: %s", x)
			}
			mask := net.CIDRMask(32, 32)
			if addr.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			cidr = &net.IPNet{
				IP:   addr,
				Mask: mask,
			}
		}
		list = append(list, *cidr)
	}
	return &NeighborSet{
		name: name,
		list: list,
	}, nil
}

type singleAsPathMatchMode int

const (
	INCLUDE singleAsPathMatchMode = iota
	LEFT_MOST
	ORIGIN
	ONLY
)

type singleAsPathMatch struct {
	asn  uint32
	mode singleAsPathMatchMode
}

func (lhs *singleAsPathMatch) Equal(rhs *singleAsPathMatch) bool {
   fmt.Printf("DEJDEJ id:",3086)
	return lhs.asn == rhs.asn && lhs.mode == rhs.mode
}

func (lhs *singleAsPathMatch) String() string {
   fmt.Printf("DEJDEJ id:",3087)
	switch lhs.mode {
	case INCLUDE:
		return fmt.Sprintf("_%d_", lhs.asn)
	case LEFT_MOST:
		return fmt.Sprintf("^%d_", lhs.asn)
	case ORIGIN:
		return fmt.Sprintf("_%d$", lhs.asn)
	case ONLY:
		return fmt.Sprintf("^%d$", lhs.asn)
	}
	return ""
}

func (m *singleAsPathMatch) Match(aspath []uint32) bool {
   fmt.Printf("DEJDEJ id:",3088)
	if len(aspath) == 0 {
		return false
	}
	switch m.mode {
	case INCLUDE:
		for _, asn := range aspath {
			if m.asn == asn {
				return true
			}
		}
	case LEFT_MOST:
		if m.asn == aspath[0] {
			return true
		}
	case ORIGIN:
		if m.asn == aspath[len(aspath)-1] {
			return true
		}
	case ONLY:
		if len(aspath) == 1 && m.asn == aspath[0] {
			return true
		}
	}
	return false
}

func NewSingleAsPathMatch(arg string) *singleAsPathMatch {
   fmt.Printf("DEJDEJ id:",3089)
	leftMostRe := regexp.MustCompile("$\\^([0-9]+)_^")
	originRe := regexp.MustCompile("^_([0-9]+)\\$$")
	includeRe := regexp.MustCompile("^_([0-9]+)_$")
	onlyRe := regexp.MustCompile("^\\^([0-9]+)\\$$")
	switch {
	case leftMostRe.MatchString(arg):
		asn, _ := strconv.ParseUint(leftMostRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: LEFT_MOST,
		}
	case originRe.MatchString(arg):
		asn, _ := strconv.ParseUint(originRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: ORIGIN,
		}
	case includeRe.MatchString(arg):
		asn, _ := strconv.ParseUint(includeRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: INCLUDE,
		}
	case onlyRe.MatchString(arg):
		asn, _ := strconv.ParseUint(onlyRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: ONLY,
		}
	}
	return nil
}

type AsPathSet struct {
	typ        DefinedType
	name       string
	list       []*regexp.Regexp
	singleList []*singleAsPathMatch
}

func (s *AsPathSet) Name() string {
   fmt.Printf("DEJDEJ id:",3090)
	return s.name
}

func (s *AsPathSet) Type() DefinedType {
   fmt.Printf("DEJDEJ id:",3091)
	return s.typ
}

func (lhs *AsPathSet) Append(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3092)
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	lhs.list = append(lhs.list, arg.(*AsPathSet).list...)
	lhs.singleList = append(lhs.singleList, arg.(*AsPathSet).singleList...)
	return nil
}

func (lhs *AsPathSet) Remove(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3093)
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	newList := make([]*regexp.Regexp, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range arg.(*AsPathSet).list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			newList = append(newList, x)
		}
	}
	lhs.list = newList
	newSingleList := make([]*singleAsPathMatch, 0, len(lhs.singleList))
	for _, x := range lhs.singleList {
		found := false
		for _, y := range arg.(*AsPathSet).singleList {
			if x.Equal(y) {
				found = true
				break
			}
		}
		if !found {
			newSingleList = append(newSingleList, x)
		}
	}
	lhs.singleList = newSingleList
	return nil
}

func (lhs *AsPathSet) Replace(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3094)
	rhs, ok := arg.(*AsPathSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	lhs.singleList = rhs.singleList
	return nil
}

func (s *AsPathSet) List() []string {
   fmt.Printf("DEJDEJ id:",3095)
	list := make([]string, 0, len(s.list)+len(s.singleList))
	for _, exp := range s.singleList {
		list = append(list, exp.String())
	}
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return list
}

func (s *AsPathSet) ToConfig() *config.AsPathSet {
   fmt.Printf("DEJDEJ id:",3096)
	return &config.AsPathSet{
		AsPathSetName: s.name,
		AsPathList:    s.List(),
	}
}

func (s *AsPathSet) String() string {
   fmt.Printf("DEJDEJ id:",3097)
	return strings.Join(s.List(), "\n")
}

func (s *AsPathSet) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3098)
	return json.Marshal(s.ToConfig())
}

func NewAsPathSet(c config.AsPathSet) (*AsPathSet, error) {
   fmt.Printf("DEJDEJ id:",3099)
	name := c.AsPathSetName
	if name == "" {
		if len(c.AsPathList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty as-path set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.AsPathList))
	singleList := make([]*singleAsPathMatch, 0, len(c.AsPathList))
	for _, x := range c.AsPathList {
		if s := NewSingleAsPathMatch(x); s != nil {
			singleList = append(singleList, s)
		} else {
			exp, err := regexp.Compile(strings.Replace(x, "_", ASPATH_REGEXP_MAGIC, -1))
			if err != nil {
				return nil, fmt.Errorf("invalid regular expression: %s", x)
			}
			list = append(list, exp)
		}
	}
	return &AsPathSet{
		typ:        DEFINED_TYPE_AS_PATH,
		name:       name,
		list:       list,
		singleList: singleList,
	}, nil
}

type regExpSet struct {
	typ  DefinedType
	name string
	list []*regexp.Regexp
}

func (s *regExpSet) Name() string {
   fmt.Printf("DEJDEJ id:",3100)
	return s.name
}

func (s *regExpSet) Type() DefinedType {
   fmt.Printf("DEJDEJ id:",3101)
	return s.typ
}

func (lhs *regExpSet) Append(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3102)
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	var list []*regexp.Regexp
	switch lhs.Type() {
	case DEFINED_TYPE_AS_PATH:
		list = arg.(*AsPathSet).list
	case DEFINED_TYPE_COMMUNITY:
		list = arg.(*CommunitySet).list
	case DEFINED_TYPE_EXT_COMMUNITY:
		list = arg.(*ExtCommunitySet).list
	case DEFINED_TYPE_LARGE_COMMUNITY:
		list = arg.(*LargeCommunitySet).list
	default:
		return fmt.Errorf("invalid defined-set type: %d", lhs.Type())
	}
	lhs.list = append(lhs.list, list...)
	return nil
}

func (lhs *regExpSet) Remove(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3103)
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	var list []*regexp.Regexp
	switch lhs.Type() {
	case DEFINED_TYPE_AS_PATH:
		list = arg.(*AsPathSet).list
	case DEFINED_TYPE_COMMUNITY:
		list = arg.(*CommunitySet).list
	case DEFINED_TYPE_EXT_COMMUNITY:
		list = arg.(*ExtCommunitySet).list
	case DEFINED_TYPE_LARGE_COMMUNITY:
		list = arg.(*LargeCommunitySet).list
	default:
		return fmt.Errorf("invalid defined-set type: %d", lhs.Type())
	}
	ps := make([]*regexp.Regexp, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			ps = append(ps, x)
		}
	}
	lhs.list = ps
	return nil
}

func (lhs *regExpSet) Replace(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3104)
	switch c := arg.(type) {
	case *CommunitySet:
		lhs.list = c.list
	case *ExtCommunitySet:
		lhs.list = c.list
	case *LargeCommunitySet:
		lhs.list = c.list
	default:
		return fmt.Errorf("type cast failed")
	}
	return nil
}

type CommunitySet struct {
	regExpSet
}

func (s *CommunitySet) List() []string {
   fmt.Printf("DEJDEJ id:",3105)
	list := make([]string, 0, len(s.list))
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return list
}

func (s *CommunitySet) ToConfig() *config.CommunitySet {
   fmt.Printf("DEJDEJ id:",3106)
	return &config.CommunitySet{
		CommunitySetName: s.name,
		CommunityList:    s.List(),
	}
}

func (s *CommunitySet) String() string {
   fmt.Printf("DEJDEJ id:",3107)
	return strings.Join(s.List(), "\n")
}

func (s *CommunitySet) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3108)
	return json.Marshal(s.ToConfig())
}

func ParseCommunity(arg string) (uint32, error) {
   fmt.Printf("DEJDEJ id:",3109)
	i, err := strconv.ParseUint(arg, 10, 32)
	if err == nil {
		return uint32(i), nil
	}
	exp := regexp.MustCompile("(\\d+):(\\d+)")
	elems := exp.FindStringSubmatch(arg)
	if len(elems) == 3 {
		fst, _ := strconv.ParseUint(elems[1], 10, 16)
		snd, _ := strconv.ParseUint(elems[2], 10, 16)
		return uint32(fst<<16 | snd), nil
	}
	for i, v := range bgp.WellKnownCommunityNameMap {
		if arg == v {
			return uint32(i), nil
		}
	}
	return 0, fmt.Errorf("failed to parse %s as community", arg)
}

func ParseExtCommunity(arg string) (bgp.ExtendedCommunityInterface, error) {
   fmt.Printf("DEJDEJ id:",3110)
	var subtype bgp.ExtendedCommunityAttrSubType
	var value string
	elems := strings.SplitN(arg, ":", 2)

	isValidationState := func(s string) bool {
		s = strings.ToLower(s)
		r := s == bgp.VALIDATION_STATE_VALID.String()
		r = r || s == bgp.VALIDATION_STATE_NOT_FOUND.String()
		return r || s == bgp.VALIDATION_STATE_INVALID.String()
	}
	if len(elems) < 2 && (len(elems) < 1 && !isValidationState(elems[0])) {
		return nil, fmt.Errorf("invalid ext-community (rt|soo):<value> | valid | not-found | invalid")
	}
	if isValidationState(elems[0]) {
		subtype = bgp.EC_SUBTYPE_ORIGIN_VALIDATION
		value = elems[0]
	} else {
		switch strings.ToLower(elems[0]) {
		case "rt":
			subtype = bgp.EC_SUBTYPE_ROUTE_TARGET
		case "soo":
			subtype = bgp.EC_SUBTYPE_ROUTE_ORIGIN
		default:
			return nil, fmt.Errorf("invalid ext-community (rt|soo):<value> | valid | not-found | invalid")
		}
		value = elems[1]
	}
	return bgp.ParseExtendedCommunity(subtype, value)
}

func ParseCommunityRegexp(arg string) (*regexp.Regexp, error) {
   fmt.Printf("DEJDEJ id:",3111)
	i, err := strconv.ParseUint(arg, 10, 32)
	if err == nil {
		return regexp.MustCompile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff)), nil
	}
	if regexp.MustCompile("(\\d+.)*\\d+:\\d+").MatchString(arg) {
		return regexp.MustCompile(fmt.Sprintf("^%s$", arg)), nil
	}
	for i, v := range bgp.WellKnownCommunityNameMap {
		if strings.Replace(strings.ToLower(arg), "_", "-", -1) == v {
			return regexp.MustCompile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff)), nil
		}
	}
	exp, err := regexp.Compile(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid community format: %s", arg)
	}
	return exp, nil
}

func ParseExtCommunityRegexp(arg string) (bgp.ExtendedCommunityAttrSubType, *regexp.Regexp, error) {
   fmt.Printf("DEJDEJ id:",3112)
	var subtype bgp.ExtendedCommunityAttrSubType
	elems := strings.SplitN(arg, ":", 2)
	if len(elems) < 2 {
		return subtype, nil, fmt.Errorf("invalid ext-community format([rt|soo]:<value>)")
	}
	switch strings.ToLower(elems[0]) {
	case "rt":
		subtype = bgp.EC_SUBTYPE_ROUTE_TARGET
	case "soo":
		subtype = bgp.EC_SUBTYPE_ROUTE_ORIGIN
	default:
		return subtype, nil, fmt.Errorf("unknown ext-community subtype. rt, soo is supported")
	}
	exp, err := ParseCommunityRegexp(elems[1])
	return subtype, exp, err
}

func NewCommunitySet(c config.CommunitySet) (*CommunitySet, error) {
   fmt.Printf("DEJDEJ id:",3113)
	name := c.CommunitySetName
	if name == "" {
		if len(c.CommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.CommunityList))
	for _, x := range c.CommunityList {
		exp, err := ParseCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
	}
	return &CommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_COMMUNITY,
			name: name,
			list: list,
		},
	}, nil
}

type ExtCommunitySet struct {
	regExpSet
	subtypeList []bgp.ExtendedCommunityAttrSubType
}

func (s *ExtCommunitySet) List() []string {
   fmt.Printf("DEJDEJ id:",3114)
	list := make([]string, 0, len(s.list))
	f := func(idx int, arg string) string {
		switch s.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
		case bgp.EC_SUBTYPE_ORIGIN_VALIDATION:
			return arg
		default:
			return fmt.Sprintf("%d:%s", s.subtypeList[idx], arg)
		}
	}
	for idx, exp := range s.list {
		list = append(list, f(idx, exp.String()))
	}
	return list
}

func (s *ExtCommunitySet) ToConfig() *config.ExtCommunitySet {
   fmt.Printf("DEJDEJ id:",3115)
	return &config.ExtCommunitySet{
		ExtCommunitySetName: s.name,
		ExtCommunityList:    s.List(),
	}
}

func (s *ExtCommunitySet) String() string {
   fmt.Printf("DEJDEJ id:",3116)
	return strings.Join(s.List(), "\n")
}

func (s *ExtCommunitySet) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3117)
	return json.Marshal(s.ToConfig())
}

func NewExtCommunitySet(c config.ExtCommunitySet) (*ExtCommunitySet, error) {
   fmt.Printf("DEJDEJ id:",3118)
	name := c.ExtCommunitySetName
	if name == "" {
		if len(c.ExtCommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty ext-community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.ExtCommunityList))
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(c.ExtCommunityList))
	for _, x := range c.ExtCommunityList {
		subtype, exp, err := ParseExtCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
		subtypeList = append(subtypeList, subtype)
	}
	return &ExtCommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_EXT_COMMUNITY,
			name: name,
			list: list,
		},
		subtypeList: subtypeList,
	}, nil
}

func (s *ExtCommunitySet) Append(arg DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3119)
	err := s.regExpSet.Append(arg)
	if err != nil {
		return err
	}
	sList := arg.(*ExtCommunitySet).subtypeList
	s.subtypeList = append(s.subtypeList, sList...)
	return nil
}

type LargeCommunitySet struct {
	regExpSet
}

func (s *LargeCommunitySet) List() []string {
   fmt.Printf("DEJDEJ id:",3120)
	list := make([]string, 0, len(s.list))
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return list
}

func (s *LargeCommunitySet) ToConfig() *config.LargeCommunitySet {
   fmt.Printf("DEJDEJ id:",3121)
	return &config.LargeCommunitySet{
		LargeCommunitySetName: s.name,
		LargeCommunityList:    s.List(),
	}
}

func (s *LargeCommunitySet) String() string {
   fmt.Printf("DEJDEJ id:",3122)
	return strings.Join(s.List(), "\n")
}

func (s *LargeCommunitySet) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3123)
	return json.Marshal(s.ToConfig())
}

func ParseLargeCommunityRegexp(arg string) (*regexp.Regexp, error) {
   fmt.Printf("DEJDEJ id:",3124)
	if regexp.MustCompile("\\d+:\\d+:\\d+").MatchString(arg) {
		return regexp.MustCompile(fmt.Sprintf("^%s$", arg)), nil
	}
	exp, err := regexp.Compile(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid large-community format: %s", arg)
	}
	return exp, nil
}

func NewLargeCommunitySet(c config.LargeCommunitySet) (*LargeCommunitySet, error) {
   fmt.Printf("DEJDEJ id:",3125)
	name := c.LargeCommunitySetName
	if name == "" {
		if len(c.LargeCommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty large community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.LargeCommunityList))
	for _, x := range c.LargeCommunityList {
		exp, err := ParseLargeCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
	}
	return &LargeCommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_LARGE_COMMUNITY,
			name: name,
			list: list,
		},
	}, nil
}

type Condition interface {
	Name() string
	Type() ConditionType
	Evaluate(*Path, *PolicyOptions) bool
	Set() DefinedSet
}

type PrefixCondition struct {
	set    *PrefixSet
	option MatchOption
}

func (c *PrefixCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3126)
	return CONDITION_PREFIX
}

func (c *PrefixCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3127)
	return c.set
}

func (c *PrefixCondition) Option() MatchOption {
   fmt.Printf("DEJDEJ id:",3128)
	return c.option
}

// compare prefixes in this condition and nlri of path and
// subsequent comparison is skipped if that matches the conditions.
// If PrefixList's length is zero, return true.
func (c *PrefixCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3129)
	var key string
	var masklen uint8
	keyf := func(ip net.IP, ones int) string {
		var buffer bytes.Buffer
		for i := 0; i < len(ip) && i < ones; i++ {
			buffer.WriteString(fmt.Sprintf("%08b", ip[i]))
		}
		return buffer.String()[:ones]
	}
	family := path.GetRouteFamily()
	switch family {
	case bgp.RF_IPv4_UC:
		masklen = path.GetNlri().(*bgp.IPAddrPrefix).Length
		key = keyf(path.GetNlri().(*bgp.IPAddrPrefix).Prefix, int(masklen))
	case bgp.RF_IPv6_UC:
		masklen = path.GetNlri().(*bgp.IPv6AddrPrefix).Length
		key = keyf(path.GetNlri().(*bgp.IPv6AddrPrefix).Prefix, int(masklen))
	default:
		return false
	}
	if family != c.set.family {
		return false
	}

	result := false
	_, ps, ok := c.set.tree.LongestPrefix(key)
	if ok {
		for _, p := range ps.([]*Prefix) {
			if p.MasklengthRangeMin <= masklen && masklen <= p.MasklengthRangeMax {
				result = true
				break
			}
		}
	}

	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}

	return result
}

func (c *PrefixCondition) Name() string { return c.set.name }
   fmt.Printf("DEJDEJ id:",3130)

func NewPrefixCondition(c config.MatchPrefixSet) (*PrefixCondition, error) {
   fmt.Printf("DEJDEJ id:",3131)
	if c.PrefixSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &PrefixCondition{
		set: &PrefixSet{
			name: c.PrefixSet,
		},
		option: o,
	}, nil
}

type NeighborCondition struct {
	set    *NeighborSet
	option MatchOption
}

func (c *NeighborCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3132)
	return CONDITION_NEIGHBOR
}

func (c *NeighborCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3133)
	return c.set
}

func (c *NeighborCondition) Option() MatchOption {
   fmt.Printf("DEJDEJ id:",3134)
	return c.option
}

// compare neighbor ipaddress of this condition and source address of path
// and, subsequent comparisons are skipped if that matches the conditions.
// If NeighborList's length is zero, return true.
func (c *NeighborCondition) Evaluate(path *Path, options *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3135)
	if len(c.set.list) == 0 {
		log.WithFields(log.Fields{
			"Topic": "Policy",
		}).Debug("NeighborList doesn't have elements")
		return true
	}

	neighbor := path.GetSource().Address
	if options != nil && options.Info != nil && options.Info.Address != nil {
		neighbor = options.Info.Address
	}

	if neighbor == nil {
		return false
	}
	result := false
	for _, n := range c.set.list {
		if n.Contains(neighbor) {
			result = true
			break
		}
	}

	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}

	return result
}

func (c *NeighborCondition) Name() string { return c.set.name }
   fmt.Printf("DEJDEJ id:",3136)

func NewNeighborCondition(c config.MatchNeighborSet) (*NeighborCondition, error) {
   fmt.Printf("DEJDEJ id:",3137)
	if c.NeighborSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &NeighborCondition{
		set: &NeighborSet{
			name: c.NeighborSet,
		},
		option: o,
	}, nil
}

type AsPathCondition struct {
	set    *AsPathSet
	option MatchOption
}

func (c *AsPathCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3138)
	return CONDITION_AS_PATH
}

func (c *AsPathCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3139)
	return c.set
}

func (c *AsPathCondition) Option() MatchOption {
   fmt.Printf("DEJDEJ id:",3140)
	return c.option
}

func (c *AsPathCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3141)
	if len(c.set.singleList) > 0 {
		aspath := path.GetAsSeqList()
		for _, m := range c.set.singleList {
			result := m.Match(aspath)
			if c.option == MATCH_OPTION_ALL && !result {
				return false
			}
			if c.option == MATCH_OPTION_ANY && result {
				return true
			}
			if c.option == MATCH_OPTION_INVERT && result {
				return false
			}
		}
	}
	if len(c.set.list) > 0 {
		aspath := path.GetAsString()
		for _, r := range c.set.list {
			result := r.MatchString(aspath)
			if c.option == MATCH_OPTION_ALL && !result {
				return false
			}
			if c.option == MATCH_OPTION_ANY && result {
				return true
			}
			if c.option == MATCH_OPTION_INVERT && result {
				return false
			}
		}
	}
	if c.option == MATCH_OPTION_ANY {
		return false
	}
	return true
}

func (c *AsPathCondition) Name() string { return c.set.name }
   fmt.Printf("DEJDEJ id:",3142)

func NewAsPathCondition(c config.MatchAsPathSet) (*AsPathCondition, error) {
   fmt.Printf("DEJDEJ id:",3143)
	if c.AsPathSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &AsPathCondition{
		set: &AsPathSet{
			name: c.AsPathSet,
		},
		option: o,
	}, nil
}

type CommunityCondition struct {
	set    *CommunitySet
	option MatchOption
}

func (c *CommunityCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3144)
	return CONDITION_COMMUNITY
}

func (c *CommunityCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3145)
	return c.set
}

func (c *CommunityCondition) Option() MatchOption {
   fmt.Printf("DEJDEJ id:",3146)
	return c.option
}

func (c *CommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3147)
	cs := path.GetCommunities()
	result := false
	for _, x := range c.set.list {
		result = false
		for _, y := range cs {
			if x.MatchString(fmt.Sprintf("%d:%d", y>>16, y&0x0000ffff)) {
				result = true
				break
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if (c.option == MATCH_OPTION_ANY || c.option == MATCH_OPTION_INVERT) && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *CommunityCondition) Name() string { return c.set.name }
   fmt.Printf("DEJDEJ id:",3148)

func NewCommunityCondition(c config.MatchCommunitySet) (*CommunityCondition, error) {
   fmt.Printf("DEJDEJ id:",3149)
	if c.CommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &CommunityCondition{
		set: &CommunitySet{
			regExpSet: regExpSet{
				name: c.CommunitySet,
			},
		},
		option: o,
	}, nil
}

type ExtCommunityCondition struct {
	set    *ExtCommunitySet
	option MatchOption
}

func (c *ExtCommunityCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3150)
	return CONDITION_EXT_COMMUNITY
}

func (c *ExtCommunityCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3151)
	return c.set
}

func (c *ExtCommunityCondition) Option() MatchOption {
   fmt.Printf("DEJDEJ id:",3152)
	return c.option
}

func (c *ExtCommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3153)
	es := path.GetExtCommunities()
	result := false
	for _, x := range es {
		result = false
		typ, subtype := x.GetTypes()
		// match only with transitive community. see RFC7153
		if typ >= 0x3f {
			continue
		}
		for idx, y := range c.set.list {
			if subtype == c.set.subtypeList[idx] && y.MatchString(x.String()) {
				result = true
				break
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if c.option == MATCH_OPTION_ANY && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *ExtCommunityCondition) Name() string { return c.set.name }
   fmt.Printf("DEJDEJ id:",3154)

func NewExtCommunityCondition(c config.MatchExtCommunitySet) (*ExtCommunityCondition, error) {
   fmt.Printf("DEJDEJ id:",3155)
	if c.ExtCommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &ExtCommunityCondition{
		set: &ExtCommunitySet{
			regExpSet: regExpSet{
				name: c.ExtCommunitySet,
			},
		},
		option: o,
	}, nil
}

type LargeCommunityCondition struct {
	set    *LargeCommunitySet
	option MatchOption
}

func (c *LargeCommunityCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3156)
	return CONDITION_LARGE_COMMUNITY
}

func (c *LargeCommunityCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3157)
	return c.set
}

func (c *LargeCommunityCondition) Option() MatchOption {
   fmt.Printf("DEJDEJ id:",3158)
	return c.option
}

func (c *LargeCommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3159)
	result := false
	cs := path.GetLargeCommunities()
	for _, x := range c.set.list {
		result = false
		for _, y := range cs {
			if x.MatchString(y.String()) {
				result = true
				break
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if (c.option == MATCH_OPTION_ANY || c.option == MATCH_OPTION_INVERT) && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *LargeCommunityCondition) Name() string { return c.set.name }
   fmt.Printf("DEJDEJ id:",3160)

func NewLargeCommunityCondition(c config.MatchLargeCommunitySet) (*LargeCommunityCondition, error) {
   fmt.Printf("DEJDEJ id:",3161)
	if c.LargeCommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &LargeCommunityCondition{
		set: &LargeCommunitySet{
			regExpSet: regExpSet{
				name: c.LargeCommunitySet,
			},
		},
		option: o,
	}, nil
}

type AsPathLengthCondition struct {
	length   uint32
	operator AttributeComparison
}

func (c *AsPathLengthCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3162)
	return CONDITION_AS_PATH_LENGTH
}

// compare AS_PATH length in the message's AS_PATH attribute with
// the one in condition.
func (c *AsPathLengthCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3163)

	length := uint32(path.GetAsPathLen())
	result := false
	switch c.operator {
	case ATTRIBUTE_EQ:
		result = c.length == length
	case ATTRIBUTE_GE:
		result = c.length <= length
	case ATTRIBUTE_LE:
		result = c.length >= length
	}

	return result
}

func (c *AsPathLengthCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3164)
	return nil
}

func (c *AsPathLengthCondition) Name() string { return "" }
   fmt.Printf("DEJDEJ id:",3165)

func (c *AsPathLengthCondition) String() string {
   fmt.Printf("DEJDEJ id:",3166)
	return fmt.Sprintf("%s%d", c.operator, c.length)
}

func NewAsPathLengthCondition(c config.AsPathLength) (*AsPathLengthCondition, error) {
   fmt.Printf("DEJDEJ id:",3167)
	if c.Value == 0 && c.Operator == "" {
		return nil, nil
	}
	var op AttributeComparison
	if i := c.Operator.ToInt(); i < 0 {
		return nil, fmt.Errorf("invalid as path length operator: %s", c.Operator)
	} else {
		// take mod 3 because we have extended openconfig attribute-comparison
		// for simple configuration. see config.AttributeComparison definition
		op = AttributeComparison(i % 3)
	}
	return &AsPathLengthCondition{
		length:   c.Value,
		operator: op,
	}, nil
}

type RpkiValidationCondition struct {
	result config.RpkiValidationResultType
}

func (c *RpkiValidationCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3168)
	return CONDITION_RPKI
}

func (c *RpkiValidationCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3169)
	return c.result == path.ValidationStatus()
}

func (c *RpkiValidationCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3170)
	return nil
}

func (c *RpkiValidationCondition) Name() string { return "" }
   fmt.Printf("DEJDEJ id:",3171)

func (c *RpkiValidationCondition) String() string {
   fmt.Printf("DEJDEJ id:",3172)
	return string(c.result)
}

func NewRpkiValidationCondition(c config.RpkiValidationResultType) (*RpkiValidationCondition, error) {
   fmt.Printf("DEJDEJ id:",3173)
	if c == config.RpkiValidationResultType("") || c == config.RPKI_VALIDATION_RESULT_TYPE_NONE {
		return nil, nil
	}
	return &RpkiValidationCondition{
		result: c,
	}, nil
}

type RouteTypeCondition struct {
	typ config.RouteType
}

func (c *RouteTypeCondition) Type() ConditionType {
   fmt.Printf("DEJDEJ id:",3174)
	return CONDITION_ROUTE_TYPE
}

func (c *RouteTypeCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3175)
	switch c.typ {
	case config.ROUTE_TYPE_LOCAL:
		return path.IsLocal()
	case config.ROUTE_TYPE_INTERNAL:
		return !path.IsLocal() && path.IsIBGP()
	case config.ROUTE_TYPE_EXTERNAL:
		return !path.IsLocal() && !path.IsIBGP()
	}
	return false
}

func (c *RouteTypeCondition) Set() DefinedSet {
   fmt.Printf("DEJDEJ id:",3176)
	return nil
}

func (c *RouteTypeCondition) Name() string { return "" }
   fmt.Printf("DEJDEJ id:",3177)

func (c *RouteTypeCondition) String() string {
   fmt.Printf("DEJDEJ id:",3178)
	return string(c.typ)
}

func NewRouteTypeCondition(c config.RouteType) (*RouteTypeCondition, error) {
   fmt.Printf("DEJDEJ id:",3179)
	if string(c) == "" || c == config.ROUTE_TYPE_NONE {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &RouteTypeCondition{
		typ: c,
	}, nil
}

type Action interface {
	Type() ActionType
	Apply(*Path, *PolicyOptions) *Path
	String() string
}

type RoutingAction struct {
	AcceptRoute bool
}

func (a *RoutingAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3180)
	return ACTION_ROUTING
}

func (a *RoutingAction) Apply(path *Path, _ *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3181)
	if a.AcceptRoute {
		return path
	}
	return nil
}

func (a *RoutingAction) String() string {
   fmt.Printf("DEJDEJ id:",3182)
	action := "reject"
	if a.AcceptRoute {
		action = "accept"
	}
	return action
}

func NewRoutingAction(c config.RouteDisposition) (*RoutingAction, error) {
   fmt.Printf("DEJDEJ id:",3183)
	var accept bool
	switch c {
	case config.RouteDisposition(""), config.ROUTE_DISPOSITION_NONE:
		return nil, nil
	case config.ROUTE_DISPOSITION_ACCEPT_ROUTE:
		accept = true
	case config.ROUTE_DISPOSITION_REJECT_ROUTE:
		accept = false
	default:
		return nil, fmt.Errorf("invalid route disposition")
	}
	return &RoutingAction{
		AcceptRoute: accept,
	}, nil
}

type CommunityAction struct {
	action     config.BgpSetCommunityOptionType
	list       []uint32
	removeList []*regexp.Regexp
}

func RegexpRemoveCommunities(path *Path, exps []*regexp.Regexp) {
   fmt.Printf("DEJDEJ id:",3184)
	comms := path.GetCommunities()
	newComms := make([]uint32, 0, len(comms))
	for _, comm := range comms {
		c := fmt.Sprintf("%d:%d", comm>>16, comm&0x0000ffff)
		match := false
		for _, exp := range exps {
			if exp.MatchString(c) {
				match = true
				break
			}
		}
		if match == false {
			newComms = append(newComms, comm)
		}
	}
	path.SetCommunities(newComms, true)
}

func RegexpRemoveExtCommunities(path *Path, exps []*regexp.Regexp, subtypes []bgp.ExtendedCommunityAttrSubType) {
   fmt.Printf("DEJDEJ id:",3185)
	comms := path.GetExtCommunities()
	newComms := make([]bgp.ExtendedCommunityInterface, 0, len(comms))
	for _, comm := range comms {
		match := false
		typ, subtype := comm.GetTypes()
		// match only with transitive community. see RFC7153
		if typ >= 0x3f {
			continue
		}
		for idx, exp := range exps {
			if subtype == subtypes[idx] && exp.MatchString(comm.String()) {
				match = true
				break
			}
		}
		if match == false {
			newComms = append(newComms, comm)
		}
	}
	path.SetExtCommunities(newComms, true)
}

func RegexpRemoveLargeCommunities(path *Path, exps []*regexp.Regexp) {
   fmt.Printf("DEJDEJ id:",3186)
	comms := path.GetLargeCommunities()
	newComms := make([]*bgp.LargeCommunity, 0, len(comms))
	for _, comm := range comms {
		c := comm.String()
		match := false
		for _, exp := range exps {
			if exp.MatchString(c) {
				match = true
				break
			}
		}
		if match == false {
			newComms = append(newComms, comm)
		}
	}
	path.SetLargeCommunities(newComms, true)
}

func (a *CommunityAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3187)
	return ACTION_COMMUNITY
}

func (a *CommunityAction) Apply(path *Path, _ *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3188)
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveCommunities(path, a.removeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetCommunities(a.list, true)
	}
	return path
}

func (a *CommunityAction) ToConfig() *config.SetCommunity {
   fmt.Printf("DEJDEJ id:",3189)
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	for _, comm := range a.list {
		c := fmt.Sprintf("%d:%d", comm>>16, comm&0x0000ffff)
		cs = append(cs, c)
	}
	for _, exp := range a.removeList {
		cs = append(cs, exp.String())
	}
	return &config.SetCommunity{
		Options:            string(a.action),
		SetCommunityMethod: config.SetCommunityMethod{CommunitiesList: cs},
	}
}

func (a *CommunityAction) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3190)
	return json.Marshal(a.ToConfig())
}

func (a *CommunityAction) String() string {
   fmt.Printf("DEJDEJ id:",3191)
	list := a.ToConfig().SetCommunityMethod.CommunitiesList
	exp := regexp.MustCompile("[\\^\\$]")
	l := exp.ReplaceAllString(strings.Join(list, ", "), "")
	return fmt.Sprintf("%s[%s]", a.action, l)
}

func NewCommunityAction(c config.SetCommunity) (*CommunityAction, error) {
   fmt.Printf("DEJDEJ id:",3192)
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []uint32
	var removeList []*regexp.Regexp
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetCommunityMethod.CommunitiesList))
	} else {
		list = make([]uint32, 0, len(c.SetCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			exp, err := ParseCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
		} else {
			comm, err := ParseCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
		}
	}
	return &CommunityAction{
		action:     a,
		list:       list,
		removeList: removeList,
	}, nil
}

type ExtCommunityAction struct {
	action      config.BgpSetCommunityOptionType
	list        []bgp.ExtendedCommunityInterface
	removeList  []*regexp.Regexp
	subtypeList []bgp.ExtendedCommunityAttrSubType
}

func (a *ExtCommunityAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3193)
	return ACTION_EXT_COMMUNITY
}

func (a *ExtCommunityAction) Apply(path *Path, _ *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3194)
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetExtCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveExtCommunities(path, a.removeList, a.subtypeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetExtCommunities(a.list, true)
	}
	return path
}

func (a *ExtCommunityAction) ToConfig() *config.SetExtCommunity {
   fmt.Printf("DEJDEJ id:",3195)
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	f := func(idx int, arg string) string {
		switch a.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
		case bgp.EC_SUBTYPE_ORIGIN_VALIDATION:
			return arg
		default:
			return fmt.Sprintf("%d:%s", a.subtypeList[idx], arg)
		}
	}
	for idx, c := range a.list {
		cs = append(cs, f(idx, c.String()))
	}
	for idx, exp := range a.removeList {
		cs = append(cs, f(idx, exp.String()))
	}
	return &config.SetExtCommunity{
		Options: string(a.action),
		SetExtCommunityMethod: config.SetExtCommunityMethod{
			CommunitiesList: cs,
		},
	}
}

func (a *ExtCommunityAction) String() string {
   fmt.Printf("DEJDEJ id:",3196)
	list := a.ToConfig().SetExtCommunityMethod.CommunitiesList
	exp := regexp.MustCompile("[\\^\\$]")
	l := exp.ReplaceAllString(strings.Join(list, ", "), "")
	return fmt.Sprintf("%s[%s]", a.action, l)
}

func (a *ExtCommunityAction) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3197)
	return json.Marshal(a.ToConfig())
}

func NewExtCommunityAction(c config.SetExtCommunity) (*ExtCommunityAction, error) {
   fmt.Printf("DEJDEJ id:",3198)
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetExtCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []bgp.ExtendedCommunityInterface
	var removeList []*regexp.Regexp
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	} else {
		list = make([]bgp.ExtendedCommunityInterface, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetExtCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			subtype, exp, err := ParseExtCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
			subtypeList = append(subtypeList, subtype)
		} else {
			comm, err := ParseExtCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
			_, subtype := comm.GetTypes()
			subtypeList = append(subtypeList, subtype)
		}
	}
	return &ExtCommunityAction{
		action:      a,
		list:        list,
		removeList:  removeList,
		subtypeList: subtypeList,
	}, nil
}

type LargeCommunityAction struct {
	action     config.BgpSetCommunityOptionType
	list       []*bgp.LargeCommunity
	removeList []*regexp.Regexp
}

func (a *LargeCommunityAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3199)
	return ACTION_LARGE_COMMUNITY
}

func (a *LargeCommunityAction) Apply(path *Path, _ *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3200)
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetLargeCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveLargeCommunities(path, a.removeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetLargeCommunities(a.list, true)
	}
	return path
}

func (a *LargeCommunityAction) ToConfig() *config.SetLargeCommunity {
   fmt.Printf("DEJDEJ id:",3201)
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	for _, comm := range a.list {
		cs = append(cs, comm.String())
	}
	for _, exp := range a.removeList {
		cs = append(cs, exp.String())
	}
	return &config.SetLargeCommunity{
		SetLargeCommunityMethod: config.SetLargeCommunityMethod{CommunitiesList: cs},
		Options:                 config.BgpSetCommunityOptionType(a.action),
	}
}

func (a *LargeCommunityAction) String() string {
   fmt.Printf("DEJDEJ id:",3202)
	list := a.ToConfig().SetLargeCommunityMethod.CommunitiesList
	exp := regexp.MustCompile("[\\^\\$]")
	l := exp.ReplaceAllString(strings.Join(list, ", "), "")
	return fmt.Sprintf("%s[%s]", a.action, l)
}

func (a *LargeCommunityAction) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3203)
	return json.Marshal(a.ToConfig())
}

func NewLargeCommunityAction(c config.SetLargeCommunity) (*LargeCommunityAction, error) {
   fmt.Printf("DEJDEJ id:",3204)
	a, ok := CommunityOptionValueMap[strings.ToLower(string(c.Options))]
	if !ok {
		if len(c.SetLargeCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []*bgp.LargeCommunity
	var removeList []*regexp.Regexp
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetLargeCommunityMethod.CommunitiesList))
	} else {
		list = make([]*bgp.LargeCommunity, 0, len(c.SetLargeCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetLargeCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			exp, err := ParseLargeCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
		} else {
			comm, err := bgp.ParseLargeCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
		}
	}
	return &LargeCommunityAction{
		action:     a,
		list:       list,
		removeList: removeList,
	}, nil

}

type MedAction struct {
	value  int64
	action MedActionType
}

func (a *MedAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3205)
	return ACTION_MED
}

func (a *MedAction) Apply(path *Path, _ *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3206)
	var err error
	switch a.action {
	case MED_ACTION_MOD:
		err = path.SetMed(a.value, false)
	case MED_ACTION_REPLACE:
		err = path.SetMed(a.value, true)
	}

	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Type":  "Med Action",
			"Error": err,
		}).Warn("Could not set Med on path")
	}
	return path
}

func (a *MedAction) ToConfig() config.BgpSetMedType {
   fmt.Printf("DEJDEJ id:",3207)
	if a.action == MED_ACTION_MOD && a.value > 0 {
		return config.BgpSetMedType(fmt.Sprintf("+%d", a.value))
	}
	return config.BgpSetMedType(fmt.Sprintf("%d", a.value))
}

func (a *MedAction) String() string {
   fmt.Printf("DEJDEJ id:",3208)
	return string(a.ToConfig())
}

func (a *MedAction) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3209)
	return json.Marshal(a.ToConfig())
}

func NewMedAction(c config.BgpSetMedType) (*MedAction, error) {
   fmt.Printf("DEJDEJ id:",3210)
	if string(c) == "" {
		return nil, nil
	}
	exp := regexp.MustCompile("^(\\+|\\-)?(\\d+)$")
	elems := exp.FindStringSubmatch(string(c))
	if len(elems) != 3 {
		return nil, fmt.Errorf("invalid med action format")
	}
	action := MED_ACTION_REPLACE
	switch elems[1] {
	case "+", "-":
		action = MED_ACTION_MOD
	}
	value, _ := strconv.ParseInt(string(c), 10, 64)
	return &MedAction{
		value:  value,
		action: action,
	}, nil
}

func NewMedActionFromApiStruct(action MedActionType, value int64) *MedAction {
   fmt.Printf("DEJDEJ id:",3211)
	return &MedAction{action: action, value: value}
}

type LocalPrefAction struct {
	value uint32
}

func (a *LocalPrefAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3212)
	return ACTION_LOCAL_PREF
}

func (a *LocalPrefAction) Apply(path *Path, _ *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3213)
	path.setPathAttr(bgp.NewPathAttributeLocalPref(a.value))
	return path
}

func (a *LocalPrefAction) ToConfig() uint32 {
   fmt.Printf("DEJDEJ id:",3214)
	return a.value
}

func (a *LocalPrefAction) String() string {
   fmt.Printf("DEJDEJ id:",3215)
	return fmt.Sprintf("%d", a.value)
}

func (a *LocalPrefAction) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3216)
	return json.Marshal(a.ToConfig())
}

func NewLocalPrefAction(value uint32) (*LocalPrefAction, error) {
   fmt.Printf("DEJDEJ id:",3217)
	if value == 0 {
		return nil, nil
	}
	return &LocalPrefAction{
		value: value,
	}, nil
}

type AsPathPrependAction struct {
	asn         uint32
	useLeftMost bool
	repeat      uint8
}

func (a *AsPathPrependAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3218)
	return ACTION_AS_PATH_PREPEND
}

func (a *AsPathPrependAction) Apply(path *Path, option *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3219)
	var asn uint32
	if a.useLeftMost {
		aspath := path.GetAsSeqList()
		if len(aspath) == 0 {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
			}).Warn("aspath length is zero.")
			return path
		}
		asn = aspath[0]
		if asn == 0 {
			log.WithFields(log.Fields{
				"Topic": "Policy",
				"Type":  "AsPathPrepend Action",
			}).Warn("left-most ASN is not seq")
			return path
		}
	} else {
		asn = a.asn
	}

	confed := option != nil && option.Info.Confederation
	path.PrependAsn(asn, a.repeat, confed)

	return path
}

func (a *AsPathPrependAction) ToConfig() *config.SetAsPathPrepend {
   fmt.Printf("DEJDEJ id:",3220)
	return &config.SetAsPathPrepend{
		RepeatN: uint8(a.repeat),
		As: func() string {
			if a.useLeftMost {
				return "last-as"
			}
			return fmt.Sprintf("%d", a.asn)
		}(),
	}
}

func (a *AsPathPrependAction) String() string {
   fmt.Printf("DEJDEJ id:",3221)
	c := a.ToConfig()
	return fmt.Sprintf("prepend %s %d times", c.As, c.RepeatN)
}

func (a *AsPathPrependAction) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3222)
	return json.Marshal(a.ToConfig())
}

// NewAsPathPrependAction creates AsPathPrependAction object.
// If ASN cannot be parsed, nil will be returned.
func NewAsPathPrependAction(action config.SetAsPathPrepend) (*AsPathPrependAction, error) {
   fmt.Printf("DEJDEJ id:",3223)
	a := &AsPathPrependAction{
		repeat: action.RepeatN,
	}
	switch action.As {
	case "":
		if a.repeat == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("specify as to prepend")
	case "last-as":
		a.useLeftMost = true
	default:
		asn, err := strconv.ParseUint(action.As, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("As number string invalid")
		}
		a.asn = uint32(asn)
	}
	return a, nil
}

type NexthopAction struct {
	value net.IP
	self  bool
}

func (a *NexthopAction) Type() ActionType {
   fmt.Printf("DEJDEJ id:",3224)
	return ACTION_NEXTHOP
}

func (a *NexthopAction) Apply(path *Path, options *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3225)
	if a.self {
		if options != nil && options.Info != nil && options.Info.LocalAddress != nil {
			path.SetNexthop(options.Info.LocalAddress)
		}
		return path
	}
	path.SetNexthop(a.value)
	return path
}

func (a *NexthopAction) ToConfig() config.BgpNextHopType {
   fmt.Printf("DEJDEJ id:",3226)
	if a.self {
		return config.BgpNextHopType("self")
	}
	return config.BgpNextHopType(a.value.String())
}

func (a *NexthopAction) String() string {
   fmt.Printf("DEJDEJ id:",3227)
	return string(a.ToConfig())
}

func (a *NexthopAction) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3228)
	return json.Marshal(a.ToConfig())
}

func NewNexthopAction(c config.BgpNextHopType) (*NexthopAction, error) {
   fmt.Printf("DEJDEJ id:",3229)
	switch strings.ToLower(string(c)) {
	case "":
		return nil, nil
	case "self":
		return &NexthopAction{
			self: true,
		}, nil
	}
	addr := net.ParseIP(string(c))
	if addr == nil {
		return nil, fmt.Errorf("invalid ip address format: %s", string(c))
	}
	return &NexthopAction{
		value: addr,
	}, nil
}

type Statement struct {
	Name        string
	Conditions  []Condition
	RouteAction Action
	ModActions  []Action
}

// evaluate each condition in the statement according to MatchSetOptions
func (s *Statement) Evaluate(p *Path, options *PolicyOptions) bool {
   fmt.Printf("DEJDEJ id:",3230)
	for _, c := range s.Conditions {
		if !c.Evaluate(p, options) {
			return false
		}
	}
	return true
}

func (s *Statement) Apply(path *Path, options *PolicyOptions) (RouteType, *Path) {
   fmt.Printf("DEJDEJ id:",3231)
	result := s.Evaluate(path, options)
	if result {
		if len(s.ModActions) != 0 {
			// apply all modification actions
			path = path.Clone(path.IsWithdraw)
			for _, action := range s.ModActions {
				path = action.Apply(path, options)
			}
		}
		//Routing action
		if s.RouteAction == nil || reflect.ValueOf(s.RouteAction).IsNil() {
			return ROUTE_TYPE_NONE, path
		}
		p := s.RouteAction.Apply(path, options)
		if p == nil {
			return ROUTE_TYPE_REJECT, path
		}
		return ROUTE_TYPE_ACCEPT, path
	}
	return ROUTE_TYPE_NONE, path
}

func (s *Statement) ToConfig() *config.Statement {
   fmt.Printf("DEJDEJ id:",3232)
	return &config.Statement{
		Name: s.Name,
		Conditions: func() config.Conditions {
			cond := config.Conditions{}
			for _, c := range s.Conditions {
				switch c.(type) {
				case *PrefixCondition:
					v := c.(*PrefixCondition)
					cond.MatchPrefixSet = config.MatchPrefixSet{PrefixSet: v.set.Name(), MatchSetOptions: v.option.ConvertToMatchSetOptionsRestrictedType()}
				case *NeighborCondition:
					v := c.(*NeighborCondition)
					cond.MatchNeighborSet = config.MatchNeighborSet{NeighborSet: v.set.Name(), MatchSetOptions: v.option.ConvertToMatchSetOptionsRestrictedType()}
				case *AsPathLengthCondition:
					v := c.(*AsPathLengthCondition)
					cond.BgpConditions.AsPathLength = config.AsPathLength{Operator: config.IntToAttributeComparisonMap[int(v.operator)], Value: v.length}
				case *AsPathCondition:
					v := c.(*AsPathCondition)
					cond.BgpConditions.MatchAsPathSet = config.MatchAsPathSet{AsPathSet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *CommunityCondition:
					v := c.(*CommunityCondition)
					cond.BgpConditions.MatchCommunitySet = config.MatchCommunitySet{CommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *ExtCommunityCondition:
					v := c.(*ExtCommunityCondition)
					cond.BgpConditions.MatchExtCommunitySet = config.MatchExtCommunitySet{ExtCommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *LargeCommunityCondition:
					v := c.(*LargeCommunityCondition)
					cond.BgpConditions.MatchLargeCommunitySet = config.MatchLargeCommunitySet{LargeCommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *RpkiValidationCondition:
					v := c.(*RpkiValidationCondition)
					cond.BgpConditions.RpkiValidationResult = v.result
				case *RouteTypeCondition:
					v := c.(*RouteTypeCondition)
					cond.BgpConditions.RouteType = v.typ
				}
			}
			return cond
		}(),
		Actions: func() config.Actions {
			act := config.Actions{}
			if s.RouteAction != nil && !reflect.ValueOf(s.RouteAction).IsNil() {
				a := s.RouteAction.(*RoutingAction)
				if a.AcceptRoute {
					act.RouteDisposition = config.ROUTE_DISPOSITION_ACCEPT_ROUTE
				} else {
					act.RouteDisposition = config.ROUTE_DISPOSITION_REJECT_ROUTE
				}
			} else {
				act.RouteDisposition = config.ROUTE_DISPOSITION_NONE
			}
			for _, a := range s.ModActions {
				switch a.(type) {
				case *AsPathPrependAction:
					act.BgpActions.SetAsPathPrepend = *a.(*AsPathPrependAction).ToConfig()
				case *CommunityAction:
					act.BgpActions.SetCommunity = *a.(*CommunityAction).ToConfig()
				case *ExtCommunityAction:
					act.BgpActions.SetExtCommunity = *a.(*ExtCommunityAction).ToConfig()
				case *LargeCommunityAction:
					act.BgpActions.SetLargeCommunity = *a.(*LargeCommunityAction).ToConfig()
				case *MedAction:
					act.BgpActions.SetMed = a.(*MedAction).ToConfig()
				case *LocalPrefAction:
					act.BgpActions.SetLocalPref = a.(*LocalPrefAction).ToConfig()
				case *NexthopAction:
					act.BgpActions.SetNextHop = a.(*NexthopAction).ToConfig()
				}
			}
			return act
		}(),
	}
}

func (s *Statement) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3233)
	return json.Marshal(s.ToConfig())
}

type opType int

const (
	ADD opType = iota
	REMOVE
	REPLACE
)

func (lhs *Statement) mod(op opType, rhs *Statement) error {
   fmt.Printf("DEJDEJ id:",3234)
	cs := make([]Condition, len(lhs.Conditions))
	copy(cs, lhs.Conditions)
	ra := lhs.RouteAction
	as := make([]Action, len(lhs.ModActions))
	copy(as, lhs.ModActions)
	for _, x := range rhs.Conditions {
		var c Condition
		i := 0
		for idx, y := range lhs.Conditions {
			if x.Type() == y.Type() {
				c = y
				i = idx
				break
			}
		}
		switch op {
		case ADD:
			if c != nil {
				return fmt.Errorf("condition %d is already set", x.Type())
			}
			if cs == nil {
				cs = make([]Condition, 0, len(rhs.Conditions))
			}
			cs = append(cs, x)
		case REMOVE:
			if c == nil {
				return fmt.Errorf("condition %d is not set", x.Type())
			}
			cs = append(cs[:i], cs[i+1:]...)
			if len(cs) == 0 {
				cs = nil
			}
		case REPLACE:
			if c == nil {
				return fmt.Errorf("condition %d is not set", x.Type())
			}
			cs[i] = x
		}
	}
	if rhs.RouteAction != nil && !reflect.ValueOf(rhs.RouteAction).IsNil() {
		switch op {
		case ADD:
			if lhs.RouteAction != nil && !reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is already set")
			}
			ra = rhs.RouteAction
		case REMOVE:
			if lhs.RouteAction == nil || reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is not set")
			}
			ra = nil
		case REPLACE:
			if lhs.RouteAction == nil || reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is not set")
			}
			ra = rhs.RouteAction
		}
	}
	for _, x := range rhs.ModActions {
		var a Action
		i := 0
		for idx, y := range lhs.ModActions {
			if x.Type() == y.Type() {
				a = y
				i = idx
				break
			}
		}
		switch op {
		case ADD:
			if a != nil {
				return fmt.Errorf("action %d is already set", x.Type())
			}
			if as == nil {
				as = make([]Action, 0, len(rhs.ModActions))
			}
			as = append(as, x)
		case REMOVE:
			if a == nil {
				return fmt.Errorf("action %d is not set", x.Type())
			}
			as = append(as[:i], as[i+1:]...)
			if len(as) == 0 {
				as = nil
			}
		case REPLACE:
			if a == nil {
				return fmt.Errorf("action %d is not set", x.Type())
			}
			as[i] = x
		}
	}
	lhs.Conditions = cs
	lhs.RouteAction = ra
	lhs.ModActions = as
	return nil
}

func (lhs *Statement) Add(rhs *Statement) error {
   fmt.Printf("DEJDEJ id:",3235)
	return lhs.mod(ADD, rhs)
}

func (lhs *Statement) Remove(rhs *Statement) error {
   fmt.Printf("DEJDEJ id:",3236)
	return lhs.mod(REMOVE, rhs)
}

func (lhs *Statement) Replace(rhs *Statement) error {
   fmt.Printf("DEJDEJ id:",3237)
	return lhs.mod(REPLACE, rhs)
}

func NewStatement(c config.Statement) (*Statement, error) {
   fmt.Printf("DEJDEJ id:",3238)
	if c.Name == "" {
		return nil, fmt.Errorf("empty statement name")
	}
	var ra Action
	var as []Action
	var cs []Condition
	var err error
	cfs := []func() (Condition, error){
		func() (Condition, error) {
			return NewPrefixCondition(c.Conditions.MatchPrefixSet)
		},
		func() (Condition, error) {
			return NewNeighborCondition(c.Conditions.MatchNeighborSet)
		},
		func() (Condition, error) {
			return NewAsPathLengthCondition(c.Conditions.BgpConditions.AsPathLength)
		},
		func() (Condition, error) {
			return NewRpkiValidationCondition(c.Conditions.BgpConditions.RpkiValidationResult)
		},
		func() (Condition, error) {
			return NewRouteTypeCondition(c.Conditions.BgpConditions.RouteType)
		},
		func() (Condition, error) {
			return NewAsPathCondition(c.Conditions.BgpConditions.MatchAsPathSet)
		},
		func() (Condition, error) {
			return NewCommunityCondition(c.Conditions.BgpConditions.MatchCommunitySet)
		},
		func() (Condition, error) {
			return NewExtCommunityCondition(c.Conditions.BgpConditions.MatchExtCommunitySet)
		},
		func() (Condition, error) {
			return NewLargeCommunityCondition(c.Conditions.BgpConditions.MatchLargeCommunitySet)
		},
	}
	cs = make([]Condition, 0, len(cfs))
	for _, f := range cfs {
		c, err := f()
		if err != nil {
			return nil, err
		}
		if !reflect.ValueOf(c).IsNil() {
			cs = append(cs, c)
		}
	}
	ra, err = NewRoutingAction(c.Actions.RouteDisposition)
	if err != nil {
		return nil, err
	}
	afs := []func() (Action, error){
		func() (Action, error) {
			return NewCommunityAction(c.Actions.BgpActions.SetCommunity)
		},
		func() (Action, error) {
			return NewExtCommunityAction(c.Actions.BgpActions.SetExtCommunity)
		},
		func() (Action, error) {
			return NewLargeCommunityAction(c.Actions.BgpActions.SetLargeCommunity)
		},
		func() (Action, error) {
			return NewMedAction(c.Actions.BgpActions.SetMed)
		},
		func() (Action, error) {
			return NewLocalPrefAction(c.Actions.BgpActions.SetLocalPref)
		},
		func() (Action, error) {
			return NewAsPathPrependAction(c.Actions.BgpActions.SetAsPathPrepend)
		},
		func() (Action, error) {
			return NewNexthopAction(c.Actions.BgpActions.SetNextHop)
		},
	}
	as = make([]Action, 0, len(afs))
	for _, f := range afs {
		a, err := f()
		if err != nil {
			return nil, err
		}
		if !reflect.ValueOf(a).IsNil() {
			as = append(as, a)
		}
	}
	return &Statement{
		Name:        c.Name,
		Conditions:  cs,
		RouteAction: ra,
		ModActions:  as,
	}, nil
}

type Policy struct {
	Name       string
	Statements []*Statement
}

// Compare path with a policy's condition in stored order in the policy.
// If a condition match, then this function stops evaluation and
// subsequent conditions are skipped.
func (p *Policy) Apply(path *Path, options *PolicyOptions) (RouteType, *Path) {
   fmt.Printf("DEJDEJ id:",3239)
	for _, stmt := range p.Statements {
		var result RouteType
		result, path = stmt.Apply(path, options)
		if result != ROUTE_TYPE_NONE {
			return result, path
		}
	}
	return ROUTE_TYPE_NONE, path
}

func (p *Policy) ToConfig() *config.PolicyDefinition {
   fmt.Printf("DEJDEJ id:",3240)
	ss := make([]config.Statement, 0, len(p.Statements))
	for _, s := range p.Statements {
		ss = append(ss, *s.ToConfig())
	}
	return &config.PolicyDefinition{
		Name:       p.Name,
		Statements: ss,
	}
}

func (p *Policy) FillUp(m map[string]*Statement) error {
   fmt.Printf("DEJDEJ id:",3241)
	stmts := make([]*Statement, 0, len(p.Statements))
	for _, x := range p.Statements {
		y, ok := m[x.Name]
		if !ok {
			return fmt.Errorf("not found statement %s", x.Name)
		}
		stmts = append(stmts, y)
	}
	p.Statements = stmts
	return nil
}

func (lhs *Policy) Add(rhs *Policy) error {
   fmt.Printf("DEJDEJ id:",3242)
	lhs.Statements = append(lhs.Statements, rhs.Statements...)
	return nil
}

func (lhs *Policy) Remove(rhs *Policy) error {
   fmt.Printf("DEJDEJ id:",3243)
	stmts := make([]*Statement, 0, len(lhs.Statements))
	for _, x := range lhs.Statements {
		found := false
		for _, y := range rhs.Statements {
			if x.Name == y.Name {
				found = true
				break
			}
		}
		if !found {
			stmts = append(stmts, x)
		}
	}
	lhs.Statements = stmts
	return nil
}

func (lhs *Policy) Replace(rhs *Policy) error {
   fmt.Printf("DEJDEJ id:",3244)
	lhs.Statements = rhs.Statements
	return nil
}

func (p *Policy) MarshalJSON() ([]byte, error) {
   fmt.Printf("DEJDEJ id:",3245)
	return json.Marshal(p.ToConfig())
}

func NewPolicy(c config.PolicyDefinition) (*Policy, error) {
   fmt.Printf("DEJDEJ id:",3246)
	if c.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	var st []*Statement
	stmts := c.Statements
	if len(stmts) != 0 {
		st = make([]*Statement, 0, len(stmts))
		for idx, stmt := range stmts {
			if stmt.Name == "" {
				stmt.Name = fmt.Sprintf("%s_stmt%d", c.Name, idx)
			}
			s, err := NewStatement(stmt)
			if err != nil {
				return nil, err
			}
			st = append(st, s)
		}
	}
	return &Policy{
		Name:       c.Name,
		Statements: st,
	}, nil
}

type Policies []*Policy

func (p Policies) Len() int {
   fmt.Printf("DEJDEJ id:",3247)
	return len(p)
}

func (p Policies) Swap(i, j int) {
   fmt.Printf("DEJDEJ id:",3248)
	p[i], p[j] = p[j], p[i]
}

func (p Policies) Less(i, j int) bool {
   fmt.Printf("DEJDEJ id:",3249)
	return p[i].Name < p[j].Name
}

type Assignment struct {
	inPolicies          []*Policy
	defaultInPolicy     RouteType
	importPolicies      []*Policy
	defaultImportPolicy RouteType
	exportPolicies      []*Policy
	defaultExportPolicy RouteType
}

type RoutingPolicy struct {
	definedSetMap DefinedSetMap
	policyMap     map[string]*Policy
	statementMap  map[string]*Statement
	assignmentMap map[string]*Assignment
	mu            sync.RWMutex
}

func (r *RoutingPolicy) ApplyPolicy(id string, dir PolicyDirection, before *Path, options *PolicyOptions) *Path {
   fmt.Printf("DEJDEJ id:",3250)
	r.mu.RLock()
	defer r.mu.RUnlock()

	if before == nil {
		return nil
	}
	if filtered := before.Filtered(id); filtered > POLICY_DIRECTION_NONE && filtered < dir {
		return nil
	}
	if before.IsWithdraw {
		return before
	}
	result := ROUTE_TYPE_NONE
	after := before
	for _, p := range r.getPolicy(id, dir) {
		result, after = p.Apply(after, options)
		if result != ROUTE_TYPE_NONE {
			break
		}
	}
	if result == ROUTE_TYPE_NONE {
		result = r.getDefaultPolicy(id, dir)
	}
	switch result {
	case ROUTE_TYPE_ACCEPT:
		return after
	default:
		return nil
	}
}

func (r *RoutingPolicy) getPolicy(id string, dir PolicyDirection) []*Policy {
   fmt.Printf("DEJDEJ id:",3251)
	a, ok := r.assignmentMap[id]
	if !ok {
		return nil
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		return a.inPolicies
	case POLICY_DIRECTION_IMPORT:
		return a.importPolicies
	case POLICY_DIRECTION_EXPORT:
		return a.exportPolicies
	default:
		return nil
	}
}

func (r *RoutingPolicy) getDefaultPolicy(id string, dir PolicyDirection) RouteType {
   fmt.Printf("DEJDEJ id:",3252)
	a, ok := r.assignmentMap[id]
	if !ok {
		return ROUTE_TYPE_NONE
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		return a.defaultInPolicy
	case POLICY_DIRECTION_IMPORT:
		return a.defaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		return a.defaultExportPolicy
	default:
		return ROUTE_TYPE_NONE
	}

}

func (r *RoutingPolicy) setPolicy(id string, dir PolicyDirection, policies []*Policy) error {
   fmt.Printf("DEJDEJ id:",3253)
	a, ok := r.assignmentMap[id]
	if !ok {
		a = &Assignment{}
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		a.inPolicies = policies
	case POLICY_DIRECTION_IMPORT:
		a.importPolicies = policies
	case POLICY_DIRECTION_EXPORT:
		a.exportPolicies = policies
	}
	r.assignmentMap[id] = a
	return nil
}

func (r *RoutingPolicy) setDefaultPolicy(id string, dir PolicyDirection, typ RouteType) error {
   fmt.Printf("DEJDEJ id:",3254)
	a, ok := r.assignmentMap[id]
	if !ok {
		a = &Assignment{}
	}
	switch dir {
	case POLICY_DIRECTION_IN:
		a.defaultInPolicy = typ
	case POLICY_DIRECTION_IMPORT:
		a.defaultImportPolicy = typ
	case POLICY_DIRECTION_EXPORT:
		a.defaultExportPolicy = typ
	}
	r.assignmentMap[id] = a
	return nil
}

func (r *RoutingPolicy) getAssignmentFromConfig(dir PolicyDirection, a config.ApplyPolicy) ([]*Policy, RouteType, error) {
   fmt.Printf("DEJDEJ id:",3255)
	var names []string
	var cdef config.DefaultPolicyType
	def := ROUTE_TYPE_ACCEPT
	c := a.Config
	switch dir {
	case POLICY_DIRECTION_IN:
		names = c.InPolicyList
		cdef = c.DefaultInPolicy
	case POLICY_DIRECTION_IMPORT:
		names = c.ImportPolicyList
		cdef = c.DefaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		names = c.ExportPolicyList
		cdef = c.DefaultExportPolicy
	default:
		return nil, def, fmt.Errorf("invalid policy direction")
	}
	if cdef == config.DEFAULT_POLICY_TYPE_REJECT_ROUTE {
		def = ROUTE_TYPE_REJECT
	}
	ps := make([]*Policy, 0, len(names))
	seen := make(map[string]bool)
	for _, name := range names {
		p, ok := r.policyMap[name]
		if !ok {
			return nil, def, fmt.Errorf("not found policy %s", name)
		}
		if seen[name] {
			return nil, def, fmt.Errorf("duplicated policy %s", name)
		}
		seen[name] = true
		ps = append(ps, p)
	}
	return ps, def, nil
}

func (r *RoutingPolicy) validateCondition(v Condition) (err error) {
   fmt.Printf("DEJDEJ id:",3256)
	switch v.Type() {
	case CONDITION_PREFIX:
		m := r.definedSetMap[DEFINED_TYPE_PREFIX]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found prefix set %s", v.Name())
		} else {
			c := v.(*PrefixCondition)
			c.set = i.(*PrefixSet)
		}
	case CONDITION_NEIGHBOR:
		m := r.definedSetMap[DEFINED_TYPE_NEIGHBOR]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found neighbor set %s", v.Name())
		} else {
			c := v.(*NeighborCondition)
			c.set = i.(*NeighborSet)
		}
	case CONDITION_AS_PATH:
		m := r.definedSetMap[DEFINED_TYPE_AS_PATH]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found as path set %s", v.Name())
		} else {
			c := v.(*AsPathCondition)
			c.set = i.(*AsPathSet)
		}
	case CONDITION_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found community set %s", v.Name())
		} else {
			c := v.(*CommunityCondition)
			c.set = i.(*CommunitySet)
		}
	case CONDITION_EXT_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_EXT_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found ext-community set %s", v.Name())
		} else {
			c := v.(*ExtCommunityCondition)
			c.set = i.(*ExtCommunitySet)
		}
	case CONDITION_LARGE_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_LARGE_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found large-community set %s", v.Name())
		} else {
			c := v.(*LargeCommunityCondition)
			c.set = i.(*LargeCommunitySet)
		}
	case CONDITION_AS_PATH_LENGTH:
	case CONDITION_RPKI:
	}
	return nil
}

func (r *RoutingPolicy) inUse(d DefinedSet) bool {
   fmt.Printf("DEJDEJ id:",3257)
	name := d.Name()
	for _, p := range r.policyMap {
		for _, s := range p.Statements {
			for _, c := range s.Conditions {
				if c.Set() != nil && c.Set().Name() == name {
					return true
				}
			}
		}
	}
	return false
}

func (r *RoutingPolicy) statementInUse(x *Statement) bool {
   fmt.Printf("DEJDEJ id:",3258)
	for _, p := range r.policyMap {
		for _, y := range p.Statements {
			if x.Name == y.Name {
				return true
			}
		}
	}
	return false
}

func (r *RoutingPolicy) reload(c config.RoutingPolicy) error {
   fmt.Printf("DEJDEJ id:",3259)
	dmap := make(map[DefinedType]map[string]DefinedSet)
	dmap[DEFINED_TYPE_PREFIX] = make(map[string]DefinedSet)
	d := c.DefinedSets
	for _, x := range d.PrefixSets {
		y, err := NewPrefixSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty prefix set")
		}
		dmap[DEFINED_TYPE_PREFIX][y.Name()] = y
	}
	dmap[DEFINED_TYPE_NEIGHBOR] = make(map[string]DefinedSet)
	for _, x := range d.NeighborSets {
		y, err := NewNeighborSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty neighbor set")
		}
		dmap[DEFINED_TYPE_NEIGHBOR][y.Name()] = y
	}
	//	dmap[DEFINED_TYPE_TAG] = make(map[string]DefinedSet)
	//	for _, x := range c.DefinedSets.TagSets{
	//		y, err := NewTagSet(x)
	//		if err != nil {
	//			return nil, err
	//		}
	//		dmap[DEFINED_TYPE_TAG][y.Name()] = y
	//	}
	bd := c.DefinedSets.BgpDefinedSets
	dmap[DEFINED_TYPE_AS_PATH] = make(map[string]DefinedSet)
	for _, x := range bd.AsPathSets {
		y, err := NewAsPathSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty as path set")
		}
		dmap[DEFINED_TYPE_AS_PATH][y.Name()] = y
	}
	dmap[DEFINED_TYPE_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.CommunitySets {
		y, err := NewCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty community set")
		}
		dmap[DEFINED_TYPE_COMMUNITY][y.Name()] = y
	}
	dmap[DEFINED_TYPE_EXT_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.ExtCommunitySets {
		y, err := NewExtCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty ext-community set")
		}
		dmap[DEFINED_TYPE_EXT_COMMUNITY][y.Name()] = y
	}
	dmap[DEFINED_TYPE_LARGE_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.LargeCommunitySets {
		y, err := NewLargeCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty large-community set")
		}
		dmap[DEFINED_TYPE_LARGE_COMMUNITY][y.Name()] = y
	}
	pmap := make(map[string]*Policy)
	smap := make(map[string]*Statement)
	for _, x := range c.PolicyDefinitions {
		y, err := NewPolicy(x)
		if err != nil {
			return err
		}
		if _, ok := pmap[y.Name]; ok {
			return fmt.Errorf("duplicated policy name. policy name must be unique.")
		}
		pmap[y.Name] = y
		for _, s := range y.Statements {
			_, ok := smap[s.Name]
			if ok {
				return fmt.Errorf("duplicated statement name. statement name must be unique.")
			}
			smap[s.Name] = s
		}
	}

	// hacky
	oldMap := r.definedSetMap
	r.definedSetMap = dmap
	for _, y := range pmap {
		for _, s := range y.Statements {
			for _, c := range s.Conditions {
				if err := r.validateCondition(c); err != nil {
					r.definedSetMap = oldMap
					return err
				}
			}
		}
	}

	r.definedSetMap = dmap
	r.policyMap = pmap
	r.statementMap = smap
	r.assignmentMap = make(map[string]*Assignment)
	// allow all routes coming in and going out by default
	r.setDefaultPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT, ROUTE_TYPE_ACCEPT)
	r.setDefaultPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, ROUTE_TYPE_ACCEPT)
	return nil
}

func (r *RoutingPolicy) GetDefinedSet(typ DefinedType, name string) (*config.DefinedSets, error) {
   fmt.Printf("DEJDEJ id:",3260)
	r.mu.RLock()
	defer r.mu.RUnlock()

	set, ok := r.definedSetMap[typ]
	if !ok {
		return nil, fmt.Errorf("invalid defined-set type: %d", typ)
	}
	sets := &config.DefinedSets{
		PrefixSets:   make([]config.PrefixSet, 0),
		NeighborSets: make([]config.NeighborSet, 0),
		BgpDefinedSets: config.BgpDefinedSets{
			CommunitySets:      make([]config.CommunitySet, 0),
			ExtCommunitySets:   make([]config.ExtCommunitySet, 0),
			LargeCommunitySets: make([]config.LargeCommunitySet, 0),
			AsPathSets:         make([]config.AsPathSet, 0),
		},
	}
	for _, s := range set {
		if name != "" && s.Name() != name {
			continue
		}
		switch s.(type) {
		case *PrefixSet:
			sets.PrefixSets = append(sets.PrefixSets, *s.(*PrefixSet).ToConfig())
		case *NeighborSet:
			sets.NeighborSets = append(sets.NeighborSets, *s.(*NeighborSet).ToConfig())
		case *CommunitySet:
			sets.BgpDefinedSets.CommunitySets = append(sets.BgpDefinedSets.CommunitySets, *s.(*CommunitySet).ToConfig())
		case *ExtCommunitySet:
			sets.BgpDefinedSets.ExtCommunitySets = append(sets.BgpDefinedSets.ExtCommunitySets, *s.(*ExtCommunitySet).ToConfig())
		case *LargeCommunitySet:
			sets.BgpDefinedSets.LargeCommunitySets = append(sets.BgpDefinedSets.LargeCommunitySets, *s.(*LargeCommunitySet).ToConfig())
		case *AsPathSet:
			sets.BgpDefinedSets.AsPathSets = append(sets.BgpDefinedSets.AsPathSets, *s.(*AsPathSet).ToConfig())
		}
	}
	return sets, nil
}

func (r *RoutingPolicy) AddDefinedSet(s DefinedSet) error {
   fmt.Printf("DEJDEJ id:",3261)
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[s.Type()]; !ok {
		return fmt.Errorf("invalid defined-set type: %d", s.Type())
	} else {
		if d, ok := m[s.Name()]; ok {
			if err := d.Append(s); err != nil {
				return err
			}
		} else {
			m[s.Name()] = s
		}
	}
	return nil
}

func (r *RoutingPolicy) DeleteDefinedSet(a DefinedSet, all bool) (err error) {
   fmt.Printf("DEJDEJ id:",3262)
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[a.Type()]; !ok {
		err = fmt.Errorf("invalid defined-set type: %d", a.Type())
	} else {
		d, ok := m[a.Name()]
		if !ok {
			return fmt.Errorf("not found defined-set: %s", a.Name())
		}
		if all {
			if r.inUse(d) {
				err = fmt.Errorf("can't delete. defined-set %s is in use", a.Name())
			} else {
				delete(m, a.Name())
			}
		} else {
			err = d.Remove(a)
		}
	}
	return err
}

func (r *RoutingPolicy) ReplaceDefinedSet(a DefinedSet) (err error) {
   fmt.Printf("DEJDEJ id:",3263)
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[a.Type()]; !ok {
		err = fmt.Errorf("invalid defined-set type: %d", a.Type())
	} else {
		if d, ok := m[a.Name()]; !ok {
			err = fmt.Errorf("not found defined-set: %s", a.Name())
		} else {
			err = d.Replace(a)
		}
	}
	return err
}

func (r *RoutingPolicy) GetStatement() []*config.Statement {
   fmt.Printf("DEJDEJ id:",3264)
	r.mu.RLock()
	defer r.mu.RUnlock()

	l := make([]*config.Statement, 0, len(r.statementMap))
	for _, st := range r.statementMap {
		l = append(l, st.ToConfig())
	}
	return l
}

func (r *RoutingPolicy) AddStatement(st *Statement) (err error) {
   fmt.Printf("DEJDEJ id:",3265)
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, c := range st.Conditions {
		if err = r.validateCondition(c); err != nil {
			return
		}
	}
	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		err = d.Add(st)
	} else {
		m[name] = st
	}

	return err
}

func (r *RoutingPolicy) DeleteStatement(st *Statement, all bool) (err error) {
   fmt.Printf("DEJDEJ id:",3266)
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		if all {
			if r.statementInUse(d) {
				err = fmt.Errorf("can't delete. statement %s is in use", name)
			} else {
				delete(m, name)
			}
		} else {
			err = d.Remove(st)
		}
	} else {
		err = fmt.Errorf("not found statement: %s", name)
	}
	return err
}

func (r *RoutingPolicy) ReplaceStatement(st *Statement) (err error) {
   fmt.Printf("DEJDEJ id:",3267)
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		err = d.Replace(st)
	} else {
		err = fmt.Errorf("not found statement: %s", name)
	}
	return err
}

func (r *RoutingPolicy) GetAllPolicy() []*config.PolicyDefinition {
   fmt.Printf("DEJDEJ id:",3268)
	r.mu.RLock()
	defer r.mu.RUnlock()

	l := make([]*config.PolicyDefinition, 0, len(r.policyMap))
	for _, p := range r.policyMap {
		l = append(l, p.ToConfig())
	}
	return l
}

func (r *RoutingPolicy) AddPolicy(x *Policy, refer bool) (err error) {
   fmt.Printf("DEJDEJ id:",3269)
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, st := range x.Statements {
		for _, c := range st.Conditions {
			if err = r.validateCondition(c); err != nil {
				return
			}
		}
	}

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if refer {
		err = x.FillUp(sMap)
	} else {
		for _, st := range x.Statements {
			if _, ok := sMap[st.Name]; ok {
				err = fmt.Errorf("statement %s already defined", st.Name)
				return
			}
			sMap[st.Name] = st
		}
	}
	if ok {
		err = y.Add(x)
	} else {
		pMap[name] = x
	}

	return err
}

func (r *RoutingPolicy) DeletePolicy(x *Policy, all, preserve bool, activeId []string) (err error) {
   fmt.Printf("DEJDEJ id:",3270)
	r.mu.Lock()
	defer r.mu.Unlock()

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if !ok {
		err = fmt.Errorf("not found policy: %s", name)
		return
	}
	inUse := func(ids []string) bool {
		for _, id := range ids {
			for _, dir := range []PolicyDirection{POLICY_DIRECTION_IN, POLICY_DIRECTION_EXPORT, POLICY_DIRECTION_EXPORT} {
				for _, y := range r.getPolicy(id, dir) {
					if x.Name == y.Name {
						return true
					}
				}
			}
		}
		return false
	}

	if all {
		if inUse(activeId) {
			err = fmt.Errorf("can't delete. policy %s is in use", name)
			return
		}
		log.WithFields(log.Fields{
			"Topic": "Policy",
			"Key":   name,
		}).Debug("delete policy")
		delete(pMap, name)
	} else {
		err = y.Remove(x)
	}
	if err == nil && !preserve {
		for _, st := range y.Statements {
			if !r.statementInUse(st) {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Key":   st.Name,
				}).Debug("delete unused statement")
				delete(sMap, st.Name)
			}
		}
	}
	return err
}

func (r *RoutingPolicy) ReplacePolicy(x *Policy, refer, preserve bool) (err error) {
   fmt.Printf("DEJDEJ id:",3271)
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, st := range x.Statements {
		for _, c := range st.Conditions {
			if err = r.validateCondition(c); err != nil {
				return
			}
		}
	}

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if !ok {
		err = fmt.Errorf("not found policy: %s", name)
		return
	}
	if refer {
		if err = x.FillUp(sMap); err != nil {
			return
		}
	} else {
		for _, st := range x.Statements {
			if _, ok := sMap[st.Name]; ok {
				err = fmt.Errorf("statement %s already defined", st.Name)
				return
			}
			sMap[st.Name] = st
		}
	}

	ys := y.Statements
	err = y.Replace(x)
	if err == nil && !preserve {
		for _, st := range ys {
			if !r.statementInUse(st) {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Key":   st.Name,
				}).Debug("delete unused statement")
				delete(sMap, st.Name)
			}
		}
	}
	return err
}

func (r *RoutingPolicy) GetPolicyAssignment(id string, dir PolicyDirection) (RouteType, []*config.PolicyDefinition, error) {
   fmt.Printf("DEJDEJ id:",3272)
	r.mu.RLock()
	defer r.mu.RUnlock()

	rt := r.getDefaultPolicy(id, dir)

	ps := r.getPolicy(id, dir)
	l := make([]*config.PolicyDefinition, 0, len(ps))
	for _, p := range ps {
		l = append(l, p.ToConfig())
	}
	return rt, l, nil
}

func (r *RoutingPolicy) AddPolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, def RouteType) (err error) {
   fmt.Printf("DEJDEJ id:",3273)
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := r.getPolicy(id, dir)
	if cur == nil {
		err = r.setPolicy(id, dir, ps)
	} else {
		seen = make(map[string]bool)
		ps = append(cur, ps...)
		for _, x := range ps {
			if seen[x.Name] {
				err = fmt.Errorf("duplicated policy %s", x.Name)
				return
			}
			seen[x.Name] = true
		}
		err = r.setPolicy(id, dir, ps)
	}
	if err == nil && def != ROUTE_TYPE_NONE {
		err = r.setDefaultPolicy(id, dir, def)
	}
	return err
}

func (r *RoutingPolicy) DeletePolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, all bool) (err error) {
   fmt.Printf("DEJDEJ id:",3274)
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := r.getPolicy(id, dir)

	if all {
		err = r.setPolicy(id, dir, nil)
		if err != nil {
			return
		}
		err = r.setDefaultPolicy(id, dir, ROUTE_TYPE_NONE)
	} else {
		l := len(cur) - len(ps)
		if l < 0 {
			// try to remove more than the assigned policies...
			l = len(cur)
		}
		n := make([]*Policy, 0, l)
		for _, y := range cur {
			found := false
			for _, x := range ps {
				if x.Name == y.Name {
					found = true
					break
				}
			}
			if !found {
				n = append(n, y)
			}
		}
		err = r.setPolicy(id, dir, n)
	}
	return err
}

func (r *RoutingPolicy) ReplacePolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, def RouteType) (err error) {
   fmt.Printf("DEJDEJ id:",3275)
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	r.getPolicy(id, dir)
	err = r.setPolicy(id, dir, ps)
	if err == nil && def != ROUTE_TYPE_NONE {
		err = r.setDefaultPolicy(id, dir, def)
	}
	return err
}

func (r *RoutingPolicy) Reset(rp *config.RoutingPolicy, ap map[string]config.ApplyPolicy) error {
   fmt.Printf("DEJDEJ id:",3276)
	r.mu.Lock()
	defer r.mu.Unlock()

	if rp != nil {
		if err := r.reload(*rp); err != nil {
			log.WithFields(log.Fields{
				"Topic": "Policy",
			}).Errorf("failed to create routing policy: %s", err)
			return err
		}
	}

	for id, c := range ap {
		for _, dir := range []PolicyDirection{POLICY_DIRECTION_IN, POLICY_DIRECTION_IMPORT, POLICY_DIRECTION_EXPORT} {
			ps, def, err := r.getAssignmentFromConfig(dir, c)
			if err != nil {
				log.WithFields(log.Fields{
					"Topic": "Policy",
					"Dir":   dir,
				}).Errorf("failed to get policy info: %s", err)
				continue
			}
			r.setDefaultPolicy(id, dir, def)
			r.setPolicy(id, dir, ps)
		}
	}
	return nil
}

func NewRoutingPolicy() *RoutingPolicy {
   fmt.Printf("DEJDEJ id:",3277)
	return &RoutingPolicy{
		definedSetMap: make(map[DefinedType]map[string]DefinedSet),
		policyMap:     make(map[string]*Policy),
		statementMap:  make(map[string]*Statement),
		assignmentMap: make(map[string]*Assignment),
	}
}

func CanImportToVrf(v *Vrf, path *Path) bool {
   fmt.Printf("DEJDEJ id:",3278)
	f := func(arg []bgp.ExtendedCommunityInterface) []string {
		ret := make([]string, 0, len(arg))
		for _, a := range arg {
			ret = append(ret, fmt.Sprintf("RT:%s", a.String()))
		}
		return ret
	}
	set, _ := NewExtCommunitySet(config.ExtCommunitySet{
		ExtCommunitySetName: v.Name,
		ExtCommunityList:    f(v.ImportRt),
	})
	matchSet := config.MatchExtCommunitySet{
		ExtCommunitySet: v.Name,
		MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
	}
	c, _ := NewExtCommunityCondition(matchSet)
	c.set = set
	return c.Evaluate(path, nil)
}

type PolicyAssignment struct {
	Name     string
	Type     PolicyDirection
	Policies []*Policy
	Default  RouteType
}
