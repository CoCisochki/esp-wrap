//go:build !linux

package esp

import "github.com/songgao/water"

// CreateTun creates a virtual TUN interface on non-Linux platforms with default OS parameters.
func CreateTun(name string) (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType: water.TUN,
	})
}
