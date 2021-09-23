//go:build !openbsd

package main

func unveil(path, permissions string) error {
	return nil
}

func unveilBlock() error {
	return nil
}
