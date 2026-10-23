// Package rfctest is the black-box RFC conformance suite for go-smtp. Its
// tests use only the public API of the server and client packages, the way a
// host would; the tests that need either package's internals live beside that
// package. CHECKLIST.md maps each RFC requirement to the tests that cover it.
package rfctest
