// Code generated by "stringer -type=PTM_STATUS"; DO NOT EDIT.

package zebra

import "fmt"

const _PTM_STATUS_name = "PTM_STATUS_DOWNPTM_STATUS_UPPTM_STATUS_UNKNOWN"

var _PTM_STATUS_index = [...]uint8{0, 15, 28, 46}

func (i PTM_STATUS) String() string { 
   fmt.Print("<<<DEJDEJ id:406::ptm_status_string.go:String>>>")
	if i >= PTM_STATUS(len(_PTM_STATUS_index)-1) {
		return fmt.Sprintf("PTM_STATUS(%d)", i)
	}
	return _PTM_STATUS_name[_PTM_STATUS_index[i]:_PTM_STATUS_index[i+1]]
}
