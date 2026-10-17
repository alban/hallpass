// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(js && wasm)

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "the Headlamp plugin's client: build it with GOOS=js GOARCH=wasm (make headlamp)")
	os.Exit(1)
}
