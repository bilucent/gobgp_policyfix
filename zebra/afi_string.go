// Code generated by "stringer -type=AFI"; DO NOT EDIT.

package zebra

import "fmt"

const _AFI_name = "AFI_IPAFI_IP6AFI_ETHERAFI_MAX"

var _AFI_index = [...]uint8{0, 6, 13, 22, 29}

func (i AFI) String() string { 
   fmt.Print("<<<DEJDEJ id:408, afi_string.go:String>>>")
	i -= 1
	if i >= AFI(len(_AFI_index)-1) {
		return fmt.Sprintf("AFI(%d)", i+1)
	}
	return _AFI_name[_AFI_index[i]:_AFI_index[i+1]]
}
