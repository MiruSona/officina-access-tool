// Package wgctl 은 살아 있는 wg 인터페이스에 피어 하나만 더하고 뺀다. 다른 피어는 안 건드린다.
package wgctl

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Controller 는 시험에서 가짜로 바꾸려고 둔 경계다.
type Controller interface {
	AddPeer(pub, psk wgtypes.Key, ip net.IP) error
	RemovePeer(pub wgtypes.Key) error
	// Handshakes 는 공개키(base64) → 마지막 핸드셰이크 시각이다. 한 번도 안 했으면 0 시각.
	Handshakes() (map[string]time.Time, error)
}

type Device struct {
	Name string // wg0
}

func (d Device) configure(peer wgtypes.PeerConfig) error {
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.ConfigureDevice(d.Name, wgtypes.Config{ReplacePeers: false, Peers: []wgtypes.PeerConfig{peer}})
}

func (d Device) AddPeer(pub, psk wgtypes.Key, ip net.IP) error {
	return d.configure(wgtypes.PeerConfig{
		PublicKey:         pub,
		PresharedKey:      &psk,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}},
	})
}

func (d Device) RemovePeer(pub wgtypes.Key) error {
	return d.configure(wgtypes.PeerConfig{PublicKey: pub, Remove: true})
}

func (d Device) Handshakes() (map[string]time.Time, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dev, err := c.Device(d.Name)
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(dev.Peers))
	for _, p := range dev.Peers {
		out[p.PublicKey.String()] = p.LastHandshakeTime
	}
	return out, nil
}
