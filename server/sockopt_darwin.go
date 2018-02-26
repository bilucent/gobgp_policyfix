// Copyright (C) 2016-2017 Nippon Telegraph and Telephone Corporation.
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
// +build darwin

package server

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func setTcpMD5SigSockopt(l *net.TCPListener, address string, key string) error { 
   fmt.Print("<<<DEJDEJ id:581, sockopt_darwin.go:setTcpMD5SigSockopt(l>>>")
	return fmt.Errorf("setting md5 is not supported")
}

func setsockoptIpTtl(fd int, family int, value int) error { 
   fmt.Print("<<<DEJDEJ id:582, sockopt_darwin.go:setsockoptIpTtl(fd>>>")
	level := syscall.IPPROTO_IP
	name := syscall.IP_TTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = syscall.IPV6_UNICAST_HOPS
	}
	return os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd, level, name, value))
}

func setListenTcpTTLSockopt(l *net.TCPListener, ttl int) error { 
   fmt.Print("<<<DEJDEJ id:583, sockopt_darwin.go:setListenTcpTTLSockopt(l>>>")
	fi, family, err := extractFileAndFamilyFromTCPListener(l)
	defer fi.Close()
	if err != nil {
		return err
	}
	return setsockoptIpTtl(int(fi.Fd()), family, ttl)
}

func setTcpTTLSockopt(conn *net.TCPConn, ttl int) error { 
   fmt.Print("<<<DEJDEJ id:584, sockopt_darwin.go:setTcpTTLSockopt(conn>>>")
	fi, family, err := extractFileAndFamilyFromTCPConn(conn)
	defer fi.Close()
	if err != nil {
		return err
	}
	return setsockoptIpTtl(int(fi.Fd()), family, ttl)
}

func setTcpMinTTLSockopt(conn *net.TCPConn, ttl int) error { 
   fmt.Print("<<<DEJDEJ id:585, sockopt_darwin.go:setTcpMinTTLSockopt(conn>>>")
	return fmt.Errorf("setting min ttl is not supported")
}
