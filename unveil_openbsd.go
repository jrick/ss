package main

import "golang.org/x/sys/unix"

func unveil(path, permissions string) error {
	return unix.Unveil(path, permissions)
}

func unveilBlock() error {
	return unix.UnveilBlock()
}
