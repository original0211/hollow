package pump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Minimal SOCKS5 client (RFC 1928, no-auth, CONNECT only) — everything the
// helper needs to dial the app's loopback SOCKS listener. The destination
// is always an IP (the netstack terminated the connection; no DNS exists
// at this layer, by design).
func socks5Connect(socksAddr string, destIP net.IP, destPort uint16, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp", socksAddr)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		c.Close()
		return nil, err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		c.Close()
		return nil, errors.New("socks5: no-auth not accepted")
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip4 := destIP.To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip16 := destIP.To16(); ip16 != nil {
		req = append(req, 0x04)
		req = append(req, ip16...)
	} else {
		c.Close()
		return nil, fmt.Errorf("socks5: bad destination IP %v", destIP)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], destPort)
	req = append(req, pb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		c.Close()
		return nil, err
	}
	if buf[0] != 0x05 {
		c.Close()
		return nil, errors.New("socks5: bad reply version")
	}
	if buf[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5: connect refused by proxy, code %d", buf[1])
	}
	switch buf[3] {
	case 0x01:
		_, err = io.ReadFull(c, buf[:6])
	case 0x04:
		_, err = io.ReadFull(c, buf[:18])
	case 0x03:
		if _, err = io.ReadFull(c, buf[:1]); err == nil {
			_, err = io.ReadFull(c, buf[:int(buf[0])+2])
		}
	default:
		err = errors.New("socks5: bad address type in reply")
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}
