//go:build linux

package main

import "syscall"

func bindToDevice(fd uintptr, dev string) error {
	if dev == "" {
		return nil
	}
	return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
}
