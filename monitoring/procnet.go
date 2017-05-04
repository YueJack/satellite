/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package monitoring

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/gravitational/trace"
)

const (
	ProcNetTCP  = "/proc/net/tcp"
	ProcNetUDP  = "/proc/net/udp"
	ProcNetUnix = "/proc/net/unix"
)

type SocketState uint8

const (
	Established SocketState = 0x01
	SynSent                 = 0x02
	SynRecv                 = 0x03
	FinWait1                = 0x04
	FinWait2                = 0x05
	TimeWait                = 0x06
	Close                   = 0x07
	CloseWait               = 0x08
	LastAck                 = 0x09
	Listen                  = 0x0A
	Closing                 = 0x0B
)

type TCPStat struct {
	LocalAddress  net.TCPAddr
	RemoteAddress net.TCPAddr
	State         SocketState
	TXQueue       uint
	RXQueue       uint
	TimerState    uint
	TimeToTimeout uint
	Retransmit    uint
	UID           uint
	Inode         uint
}

type UDPStat struct {
	LocalAddress  net.UDPAddr
	RemoteAddress net.UDPAddr
	State         SocketState
	TXQueue       uint
	RXQueue       uint
	UID           uint
	Inode         uint
	RefCount      uint
	Pointer       uintptr
	Drops         uint
}

type UnixStat struct {
	RefCount uint
	Protocol uint
	Flags    uint
	Type     uint
	State    uint
	Inode    uint
	Path     string
}

func ParseProcNetTCP() ([]*TCPStat, error) {
	fp, err := os.Open(ProcNetTCP)
	defer fp.Close()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lineScanner := bufio.NewScanner(fp)
	lineScanner.Scan() // Drop header line
	var stats []*TCPStat
	for lineScanner.Scan() {
		stat, err := NewTCPStatFromLine(lineScanner.Text())
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	if err := lineScanner.Err(); err != nil {
		return nil, trace.Wrap(err)
	}
	return stats, nil
}

func ParseProcNetUDP() ([]*UDPStat, error) {
	fp, err := os.Open(ProcNetUDP)
	defer fp.Close()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lineScanner := bufio.NewScanner(fp)
	lineScanner.Scan() // Drop header line
	var stats []*UDPStat
	for lineScanner.Scan() {
		stat, err := NewUDPStatFromLine(lineScanner.Text())
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	if err := lineScanner.Err(); err != nil {
		return nil, trace.Wrap(err)
	}
	return stats, nil
}

func ParseProcNetUnix() ([]*UnixStat, error) {
	fp, err := os.Open(ProcNetUnix)
	defer fp.Close()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	lineScanner := bufio.NewScanner(fp)
	lineScanner.Scan() // Drop header line
	var stats []*UnixStat
	for lineScanner.Scan() {
		stat, err := NewUnixStatFromLine(lineScanner.Text())
		if err != nil {
			return nil, err
		}
		stats = append(stats, stat)
	}
	if err := lineScanner.Err(); err != nil {
		return nil, trace.Wrap(err)
	}
	return stats, nil
}

func NewTCPStatFromLine(line string) (*TCPStat, error) {
	// sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
	//  0: 00000000:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 18616 1 ffff91e759d47080 100 0 0 10 0
	// reference: https://github.com/ecki/net-tools/blob/master/netstat.c#L1070
	var (
		sl         int
		localip    uint32
		remoteip   uint32
		tr         int
		tmwhen     int
		retransmit int
		timeout    int
		tails      string
	)
	tcpStat := &TCPStat{}
	_, err := fmt.Sscanf(line, "%d: %X:%X %X:%X %X %X:%X %X:%X %X %d %d %d %s",
		&sl, &localip, &tcpStat.LocalAddress.Port, &remoteip, &tcpStat.RemoteAddress.Port,
		&tcpStat.State, &tcpStat.TXQueue, &tcpStat.RXQueue, &tr, &tmwhen, &retransmit,
		&tcpStat.UID, &timeout, &tcpStat.Inode, &tails)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tcpStat.LocalAddress.IP = intToIPv4(localip)
	tcpStat.RemoteAddress.IP = intToIPv4(remoteip)
	return tcpStat, nil
}

func NewUDPStatFromLine(line string) (*UDPStat, error) {
	//    sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
	//  2511: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1662497 2 ffff91e6a9fcbc00 0
	var (
		sl         int
		localip    uint32
		remoteip   uint32
		tr         int
		tmwhen     int
		retransmit int
		timeout    int
	)
	udpStat := &UDPStat{}
	_, err := fmt.Sscanf(line, "%d: %X:%X %X:%X %X %X:%X %X:%X %X %d %d %d %d %X %d",
		&sl, &localip, &udpStat.LocalAddress.Port, &remoteip, &udpStat.RemoteAddress.Port,
		&udpStat.State, &udpStat.TXQueue, &udpStat.RXQueue, &tr, &tmwhen, &retransmit,
		&udpStat.UID, &timeout, &udpStat.Inode, &udpStat.RefCount, &udpStat.Pointer,
		&udpStat.Drops)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	udpStat.LocalAddress.IP = intToIPv4(localip)
	udpStat.RemoteAddress.IP = intToIPv4(remoteip)
	return udpStat, nil
}

func NewUnixStatFromLine(line string) (*UnixStat, error) {
	// Num               RefCount Protocol Flags    Type St Inode Path
	// ffff91e759dfb800: 00000002 00000000 00010000 0001 01 16163 /tmp/sddm-auth3949710e-7c3f-4aa2-b5fc-25cc34a7f31e
	var (
		pointer uintptr
	)
	unixStat := &UnixStat{}
	n, err := fmt.Sscanf(line, "%X: %X %X %X %X %X %d %s",
		&pointer, &unixStat.RefCount, &unixStat.Protocol, &unixStat.Flags,
		&unixStat.Type, &unixStat.State, &unixStat.Inode, &unixStat.Path)
	if err != nil && n < 7 {
		return nil, trace.Wrap(err)
	}
	return unixStat, nil
}

func intToIPv4(n uint32) net.IP {
	ip := make([]byte, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return net.IPv4(ip[0], ip[1], ip[2], ip[3])
}
