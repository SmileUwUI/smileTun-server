package server

import (
	"fmt"
	"net"
	"os/exec"
	"sync"

	"github.com/songgao/water"
)

type LinuxTunnel struct {
	iface   *water.Interface
	name    string
	ip      net.IP
	netmask net.IPMask
	mtu     int
	running bool
	mu      sync.RWMutex
	stats   TunnelStats
}

type TunnelStats struct {
	RXBytes   uint64
	RXPackets uint64
	TXBytes   uint64
	TXPackets uint64
	LastError error
}

func NewTunnel(name string, mtu int, address net.IP, netmask net.IPMask) (*LinuxTunnel, error) {
	waterConfig := water.Config{
		DeviceType: water.TUN,
	}

	if name != "" {
		waterConfig.Name = name
	}

	iface, err := water.New(waterConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN: %w", err)
	}

	tunnel := &LinuxTunnel{
		iface:   iface,
		name:    iface.Name(),
		mtu:     mtu,
		running: false,
	}

	if address != nil {
		if err := tunnel.SetIP(address, netmask); err != nil {
			return nil, err
		}
	}

	if mtu > 0 {
		err = tunnel.SetMTU(mtu)
		if err != nil {
			return nil, err
		}
	}

	return tunnel, nil
}

func (t *LinuxTunnel) Name() string {
	return t.name
}

func (t *LinuxTunnel) Read(packet []byte) (int, error) {
	return t.iface.Read(packet)
}

func (t *LinuxTunnel) Write(packet []byte) (int, error) {
	return t.iface.Write(packet)
}

func (t *LinuxTunnel) IP() net.IP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ip
}

func (t *LinuxTunnel) Netmask() net.IPMask {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.netmask
}

func (t *LinuxTunnel) MTU() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mtu
}

func (t *LinuxTunnel) SetIP(ip net.IP, netmask net.IPMask) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.ip != nil {
		// #nosec G204
		err := exec.Command("ip", "addr", "del",
			fmt.Sprintf("%s/%d", t.ip, t.getPrefixLen()),
			"dev", t.name).Run()
		if err != nil {
			return err
		}
	}

	prefixLen, _ := netmask.Size()
	// #nosec G204
	cmd := exec.Command("ip", "addr", "add",
		fmt.Sprintf("%s/%d", ip.String(), prefixLen),
		"dev", t.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP: %w", err)
	}

	t.ip = ip
	t.netmask = netmask
	return nil
}

func (t *LinuxTunnel) SetMTU(mtu int) error {
	// #nosec G204
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", mtu))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}
	t.mtu = mtu
	return nil
}

func (t *LinuxTunnel) Up() error {
	// #nosec G204
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}
	t.running = true
	return nil
}

func (t *LinuxTunnel) Down() error {
	// #nosec G204
	cmd := exec.Command("ip", "link", "set", "dev", t.name, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring down interface: %w", err)
	}
	t.running = false
	return nil
}

func (t *LinuxTunnel) Close() error {
	err := t.Down()
	if err != nil {
		return err
	}

	return t.iface.Close()
}

func (t *LinuxTunnel) IsRunning() bool {
	return t.running
}

func (t *LinuxTunnel) Stats() (*TunnelStats, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := &TunnelStats{
		RXBytes:   t.stats.RXBytes,
		RXPackets: t.stats.RXPackets,
		TXBytes:   t.stats.TXBytes,
		TXPackets: t.stats.TXPackets,
	}

	return stats, nil
}

func (t *LinuxTunnel) getPrefixLen() int {
	if t.netmask == nil {
		return 24
	}
	size, _ := t.netmask.Size()
	return size
}
