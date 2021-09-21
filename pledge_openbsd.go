package main

import "golang.org/x/sys/unix"

func pledge(promises string) error {
	return unix.PledgePromises(promises)
}
