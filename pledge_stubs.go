//go:build !openbsd

package main

func pledge(promises string) error {
	return nil
}
