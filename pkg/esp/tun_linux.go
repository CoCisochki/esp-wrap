//go:build linux

package esp

import "github.com/songgao/water"

// CreateTun creates a virtual TUN interface on Linux with the specified interface name.
func CreateTun(name string) (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	})
}
