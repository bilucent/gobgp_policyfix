// Code generated by "stringer -type=ROUTE_TYPE"; DO NOT EDIT.

package zebra

import "fmt"

const _ROUTE_TYPE_name = "ROUTE_SYSTEMROUTE_KERNELROUTE_CONNECTROUTE_STATICROUTE_RIPROUTE_RIPNGROUTE_OSPFROUTE_OSPF6ROUTE_ISISROUTE_BGPROUTE_PIMROUTE_HSLSROUTE_OLSRROUTE_BABELROUTE_MAXFRR_ROUTE_VNCFRR_ROUTE_VNC_DIRECTFRR_ROUTE_VNC_DIRECT_RHFRR_ROUTE_BGP_DIRECTFRR_ROUTE_BGP_DIRECT_EXTFRR_ROUTE_ALLFRR_ROUTE_MAX"

var _ROUTE_TYPE_index = [...]uint16{0, 12, 24, 37, 49, 58, 69, 79, 90, 100, 109, 118, 128, 138, 149, 158, 171, 191, 214, 234, 258, 271, 284}

func (i ROUTE_TYPE) String() string { 
   fmt.Print("<<<DEJDEJ id:405, route_type_string.go:String>>>")
	if i >= ROUTE_TYPE(len(_ROUTE_TYPE_index)-1) {
		return fmt.Sprintf("ROUTE_TYPE(%d)", i)
	}
	return _ROUTE_TYPE_name[_ROUTE_TYPE_index[i]:_ROUTE_TYPE_index[i+1]]
}
