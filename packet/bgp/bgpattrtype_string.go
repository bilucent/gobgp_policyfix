// generated by stringer -type BGPAttrType bgp.go; DO NOT EDIT

package bgp

import "fmt"

const (
	_BGPAttrType_name_0 = "BGP_ATTR_TYPE_ORIGINBGP_ATTR_TYPE_AS_PATHBGP_ATTR_TYPE_NEXT_HOPBGP_ATTR_TYPE_MULTI_EXIT_DISCBGP_ATTR_TYPE_LOCAL_PREFBGP_ATTR_TYPE_ATOMIC_AGGREGATEBGP_ATTR_TYPE_AGGREGATORBGP_ATTR_TYPE_COMMUNITIESBGP_ATTR_TYPE_ORIGINATOR_IDBGP_ATTR_TYPE_CLUSTER_LIST"
	_BGPAttrType_name_1 = "BGP_ATTR_TYPE_MP_REACH_NLRIBGP_ATTR_TYPE_MP_UNREACH_NLRIBGP_ATTR_TYPE_EXTENDED_COMMUNITIESBGP_ATTR_TYPE_AS4_PATHBGP_ATTR_TYPE_AS4_AGGREGATOR"
)

var (
	_BGPAttrType_index_0 = [...]uint8{0, 20, 41, 63, 92, 116, 146, 170, 195, 222, 248}
	_BGPAttrType_index_1 = [...]uint8{0, 27, 56, 90, 112, 140}
)

func (i BGPAttrType) String() string {
   fmt.Printf("DEJDEJ id:",2664)
	switch {
	case 1 <= i && i <= 10:
		i -= 1
		return _BGPAttrType_name_0[_BGPAttrType_index_0[i]:_BGPAttrType_index_0[i+1]]
	case 14 <= i && i <= 18:
		i -= 14
		return _BGPAttrType_name_1[_BGPAttrType_index_1[i]:_BGPAttrType_index_1[i+1]]
	default:
		return fmt.Sprintf("BGPAttrType(%d)", i)
	}
}
