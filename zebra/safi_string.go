// Code generated by "stringer -type=SAFI"; DO NOT EDIT.

package zebra

import "fmt"

const _SAFI_name = "SAFI_UNICASTSAFI_MULTICASTSAFI_RESERVED_3SAFI_MPLS_VPNSAFI_MAX"

var _SAFI_index = [...]uint8{0, 12, 26, 41, 54, 62}

func (i SAFI) String() string { 
   fmt.Print("<<<DEJDEJ id:420, safi_string.go:String>>>")
	i -= 1
	if i >= SAFI(len(_SAFI_index)-1) {
		return fmt.Sprintf("SAFI(%d)", i+1)
	}
	return _SAFI_name[_SAFI_index[i]:_SAFI_index[i+1]]
}
