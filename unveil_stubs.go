//go:build !openbsd

package main

func unveil(path, flags string) error {
	return nil
}

func unveilBlock() error {
	return nil
}
