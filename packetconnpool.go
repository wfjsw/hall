package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/net/ipv4"
)

type PacketConnSubPool struct {
	conns []*ipv4.PacketConn
	iter  int
}

type PacketConnPool struct {
	m     sync.Mutex
	conns map[string]*PacketConnSubPool
	cap   int

	Factory func(net.IP) (*ipv4.PacketConn, error)
	Close   func(*ipv4.PacketConn) error
}

func NewPacketConnPool(cap int, factory func(net.IP) (*ipv4.PacketConn, error), close func(*ipv4.PacketConn) error) (*PacketConnPool, error) {
	if cap == 0 {
		cap = runtime.NumCPU()
	}

	if factory == nil {
		return nil, errors.New("Invalid factory")
	}

	if close == nil {
		return nil, errors.New("Invalid close")
	}

	c := &PacketConnPool{
		conns:   make(map[string]*PacketConnSubPool),
		cap:     cap,
		Factory: factory,
		Close:   close,
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ifIPv4 := ip.To4(); ifIPv4 == nil {
				continue
			}

			// process IP address
			c.conns[ip.String()] = &PacketConnSubPool{
				conns: make([]*ipv4.PacketConn, cap),
				iter:  0,
			}

			for i := 0; i < cap; i++ {
				conn, err := c.Factory(ip)
				if err != nil {
					c.Destory()
					return nil, fmt.Errorf("factory is not able to fill the pool: %s", err)
				}
				c.conns[ip.String()].conns[i] = conn
			}
		}
	}

	return c, nil
}

func (p *PacketConnPool) Pick(ip string) *ipv4.PacketConn {
	p.m.Lock()
	defer p.m.Unlock()
	group, exists := p.conns[ip]
	if !exists {
		return nil
	}
	n := group.iter
	group.iter++
	if group.iter >= p.cap {
		group.iter = 0
	}

	return group.conns[n]
}

func (p *PacketConnPool) Destory() {
	p.m.Lock()
	defer p.m.Unlock()
	for _, iface := range p.conns {
		for _, sck := range iface.conns {
			_ = p.Close(sck)
		}
	}
}

func (server *Server) udpConnFactory(host net.IP) (*ipv4.PacketConn, error) {
	// host := server.HostAddress()
	port := server.Port()

	laddr := &net.UDPAddr{
		// IP:   net.ParseIP(host),
		IP:   host,
		Port: port,
	}

	lcfg := net.ListenConfig{
		Control: reuseControl,
	}

	conn, err := lcfg.ListenPacket(context.Background(), "udp4", laddr.String())
	if err != nil {
		return nil, err
	}

	bufSize := server.cfg.UDPBufferSize * 1024
	if bufSize == 0 {
		bufSize = server.maxUsers() * UDPPacketSize * 8
	}

	switch conn.(type) {
	case *net.UDPConn:
		conn.(*net.UDPConn).SetReadBuffer(bufSize)
		conn.(*net.UDPConn).SetWriteBuffer(bufSize)
	}

	pc := ipv4.NewPacketConn(conn)

	go server.udpListenLoop(pc)

	return pc, nil
}

func (server *Server) udpConnDestory(conn *ipv4.PacketConn) error {
	return conn.Close()
}
