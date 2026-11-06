//go:build !linux

package main

func bindToDevice(fd uintptr, dev string) error {
	return nil
}
