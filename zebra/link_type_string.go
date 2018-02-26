// Code generated by "stringer -type=LINK_TYPE"; DO NOT EDIT.

package zebra

import "fmt"

const _LINK_TYPE_name = "LINK_TYPE_UNKNOWNLINK_TYPE_ETHERLINK_TYPE_EETHERLINK_TYPE_AX25LINK_TYPE_PRONETLINK_TYPE_IEEE802LINK_TYPE_ARCNETLINK_TYPE_APPLETLKLINK_TYPE_DLCILINK_TYPE_ATMLINK_TYPE_METRICOMLINK_TYPE_IEEE1394LINK_TYPE_EUI64LINK_TYPE_INFINIBANDLINK_TYPE_SLIPLINK_TYPE_CSLIPLINK_TYPE_SLIP6LINK_TYPE_CSLIP6LINK_TYPE_RSRVDLINK_TYPE_ADAPTLINK_TYPE_ROSELINK_TYPE_X25LINK_TYPE_PPPLINK_TYPE_CHDLCLINK_TYPE_LAPBLINK_TYPE_RAWHDLCLINK_TYPE_IPIPLINK_TYPE_IPIP6LINK_TYPE_FRADLINK_TYPE_SKIPLINK_TYPE_LOOPBACKLINK_TYPE_LOCALTLKLINK_TYPE_FDDILINK_TYPE_SITLINK_TYPE_IPDDPLINK_TYPE_IPGRELINK_TYPE_IP6GRELINK_TYPE_PIMREGLINK_TYPE_HIPPILINK_TYPE_ECONETLINK_TYPE_IRDALINK_TYPE_FCPPLINK_TYPE_FCALLINK_TYPE_FCPLLINK_TYPE_FCFABRICLINK_TYPE_IEEE802_TRLINK_TYPE_IEEE80211LINK_TYPE_IEEE80211_RADIOTAPLINK_TYPE_IEEE802154LINK_TYPE_IEEE802154_PHY"

var _LINK_TYPE_index = [...]uint16{0, 17, 32, 48, 62, 78, 95, 111, 129, 143, 156, 174, 192, 207, 227, 241, 256, 271, 287, 302, 317, 331, 344, 357, 372, 386, 403, 417, 432, 446, 460, 478, 496, 510, 523, 538, 553, 569, 585, 600, 616, 630, 644, 658, 672, 690, 710, 729, 757, 777, 801}

func (i LINK_TYPE) String() string { 
	if i >= LINK_TYPE(len(_LINK_TYPE_index)-1) {
		return fmt.Sprintf("LINK_TYPE(%d)", i)
	}
	return _LINK_TYPE_name[_LINK_TYPE_index[i]:_LINK_TYPE_index[i+1]]
}
