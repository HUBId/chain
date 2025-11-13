//go:build !go1.25

//go:debug cgocheck=1

package ffi

// This file exists solely to enforce that Firewood's Go tests run with
// cgocheck enabled on toolchains that still support configuring it via the
// //go:debug directive. Go 1.25 and newer removed support for toggling
// cgocheck through //go:debug, so the file is excluded there.
