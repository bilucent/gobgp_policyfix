// generated by stringer -type=FSMState -output=fsmstate_string.go bgp.go validate.go mrt.go rtr.go constant.go bmp.go esitype_string.go bgpattrtype_string.go; DO NOT EDIT

package bgp

import "fmt"

const _FSMState_name = "BGP_FSM_IDLEBGP_FSM_CONNECTBGP_FSM_ACTIVEBGP_FSM_OPENSENTBGP_FSM_OPENCONFIRMBGP_FSM_ESTABLISHED"

var _FSMState_index = [...]uint8{0, 12, 27, 41, 57, 76, 95}

func (i FSMState) String() string {    fmt.Printf("DEJDEJ id:",2663)

	if i < 0 || i >= FSMState(len(_FSMState_index)-1) {
		return fmt.Sprintf("FSMState(%d)", i)
	}
	return _FSMState_name[_FSMState_index[i]:_FSMState_index[i+1]]
}
