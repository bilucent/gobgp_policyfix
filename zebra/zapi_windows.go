// Copyright (C) 2014, 2015 Nippon Telegraph and Telephone Corporation.
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

package zebra

import (
  "fmt"
	"strings"
	"syscall"
)

func intfflag2string(flag uint64) string { 
   fmt.Print("<<<DEJDEJ id:422, zapi_windows.go:intfflag2string(flag>>>")
	ss := make([]string, 0, 10)
	if flag&syscall.IFF_UP > 0 {
		ss = append(ss, "UP")
	}
	if flag&syscall.IFF_BROADCAST > 0 {
		ss = append(ss, "BROADCAST")
	}
	if flag&syscall.IFF_LOOPBACK > 0 {
		ss = append(ss, "LOOPBACK")
	}
	if flag&syscall.IFF_MULTICAST > 0 {
		ss = append(ss, "MULTICAST")
	}
	return strings.Join(ss, " | ")
}
