package dns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/AtDexters-Lab/namek-server/internal/metrics"
)

const (
	udpBufSize       = 4096
	udpMaxConcurrent = 512
	tcpMaxConcurrent = 100
	tcpTotalTimeout  = 30 * time.Second
)

var udpRespPool = sync.Pool{
	New: func() any { return make([]byte, udpBufSize) },
}

// Proxy forwards DNS traffic from a listen address to an upstream address.
type Proxy struct {
	listenAddr   string
	upstreamAddr string
	logger       *slog.Logger

	udpConn net.PacketConn
	tcpLn   net.Listener
	wg      sync.WaitGroup
}

// NewProxy creates a DNS proxy that forwards traffic from listenAddr to upstreamAddr.
func NewProxy(listenAddr, upstreamAddr string, logger *slog.Logger) *Proxy {
	return &Proxy{
		listenAddr:   listenAddr,
		upstreamAddr: upstreamAddr,
		logger:       logger,
	}
}

// Start begins listening on UDP and TCP for DNS traffic.
func (p *Proxy) Start(ctx context.Context) error {
	var err error

	p.udpConn, err = net.ListenPacket("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("dns proxy udp listen: %w", err)
	}

	p.tcpLn, err = net.Listen("tcp", p.listenAddr)
	if err != nil {
		p.udpConn.Close()
		return fmt.Errorf("dns proxy tcp listen: %w", err)
	}

	p.logger.Info("dns proxy started", "listen", p.listenAddr, "upstream", p.upstreamAddr)

	p.wg.Add(2)
	go p.serveUDP(ctx)
	go p.serveTCP(ctx)

	return nil
}

// Close shuts down the proxy and waits for all goroutines to finish.
func (p *Proxy) Close() {
	if p.udpConn != nil {
		p.udpConn.Close()
	}
	if p.tcpLn != nil {
		p.tcpLn.Close()
	}
	p.wg.Wait()
}

func (p *Proxy) serveUDP(ctx context.Context) {
	defer p.wg.Done()

	var handlers sync.WaitGroup
	defer handlers.Wait()

	sem := make(chan struct{}, udpMaxConcurrent)
	buf := make([]byte, udpBufSize)

	for {
		n, clientAddr, err := p.udpConn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.logger.Error("dns proxy udp read", "error", err)
			return
		}

		metrics.Get().DNS.UDPQueries.Add(1)

		select {
		case sem <- struct{}{}:
		default:
			metrics.Get().DNS.UDPDropped.Add(1)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { <-sem }()
			p.handleUDP(packet, clientAddr)
		}()
	}
}

// handleUDP forwards a single DNS query to upstream and relays the response.
// Each call opens a new UDP socket. This is acceptable for a loopback proxy
// but could exhaust ephemeral ports under very high throughput.
func (p *Proxy) handleUDP(query []byte, clientAddr net.Addr) {
	upstream, err := net.Dial("udp", p.upstreamAddr)
	if err != nil {
		metrics.Get().DNS.Errors.Add(1)
		p.logger.Error("dns proxy udp dial upstream", "error", err)
		return
	}
	defer upstream.Close()

	upstream.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := upstream.Write(query); err != nil {
		metrics.Get().DNS.Errors.Add(1)
		p.logger.Error("dns proxy udp write upstream", "error", err)
		return
	}

	resp := udpRespPool.Get().([]byte)
	defer udpRespPool.Put(resp)

	n, err := upstream.Read(resp)
	if err != nil {
		metrics.Get().DNS.Errors.Add(1)
		p.logger.Error("dns proxy udp read upstream", "error", err)
		return
	}

	if _, err := p.udpConn.WriteTo(resp[:n], clientAddr); err != nil {
		metrics.Get().DNS.Errors.Add(1)
		p.logger.Error("dns proxy udp write client", "error", err)
	}
}

func (p *Proxy) serveTCP(ctx context.Context) {
	defer p.wg.Done()

	var handlers sync.WaitGroup
	defer handlers.Wait()

	sem := make(chan struct{}, tcpMaxConcurrent)

	for {
		conn, err := p.tcpLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.logger.Error("dns proxy tcp accept", "error", err)
			return
		}

		metrics.Get().DNS.TCPQueries.Add(1)

		select {
		case sem <- struct{}{}:
		default:
			metrics.Get().DNS.TCPDropped.Add(1)
			conn.Close()
			continue
		}

		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { <-sem }()
			p.handleTCP(conn)
		}()
	}
}

func (p *Proxy) handleTCP(client net.Conn) {
	defer client.Close()

	client.SetDeadline(time.Now().Add(tcpTotalTimeout))

	upstream, err := net.DialTimeout("tcp", p.upstreamAddr, 5*time.Second)
	if err != nil {
		metrics.Get().DNS.Errors.Add(1)
		p.logger.Error("dns proxy tcp dial upstream", "error", err)
		return
	}
	defer upstream.Close()

	upstream.SetDeadline(time.Now().Add(tcpTotalTimeout))

	done := make(chan struct{})
	go func() {
		io.Copy(upstream, client)
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		close(done)
	}()

	io.Copy(client, upstream)
	<-done
}
