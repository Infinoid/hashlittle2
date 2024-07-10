# Hashlittle2

This is a pure Go implementation of the `hashlittle2` hash function, from the `lookup3` family of hash functions by Bob Jenkins.  It is a non-cryptographic, 64 bit hash function.

I did not implement this from scratch; I merely adapted existing code for my own purposes.  See Credits, below.

# Usage

```go
	hl2 := hashlittle2.HashLittle2()
	hl2.Write([]byte("Hello, world!"))
	fmt.Printf("%#x\n", hl2.Sum64()) // prints 0xe44bd6e48deb0e18
```

# Compatibility

This function is compatible with the hashes used by older (pre-v246, ~2020) versions of `systemd` journal files.  More details can be found in their [journal file format document](https://github.com/systemd/systemd/blob/main/docs/JOURNAL_FILE_FORMAT.md?plain=1#L71-L73).

# Credits

This implementation was based on [Apsalar/lookup3](https://github.com/Apsalar/lookup3), which implements the closely related `hashlittle` function.  The internal workings of these two functions are identical, just with differing input and output widths (32-bit vs 64-bit).

The original C version by Bob Jenkins can be found in [lookup3.c](https://burtleburtle.net/bob/c/lookup3.c).

Massive thanks to all involved.
