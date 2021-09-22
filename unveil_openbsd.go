package main

import "golang.org/x/sys/unix"

func unveil(path, flags string) error {
	return unix.Unveil(path, flags)
}

func unveilBlock() error {
	return unix.UnveilBlock()
}
