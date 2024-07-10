// based on https://github.com/Apsalar/lookup3/blob/master/lookup3_test.go
// It was adapted for 64-bit hashes, as described in the systemd journal format document.

package hashlittle2

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

type golden struct {
	sum  []byte
	u64  uint64
	text string
}

var golden32 = []golden{
	{[]byte{0xde, 0xad, 0xbe, 0xef}, 0xdeadbeef, ""},
	{[]byte{0x58, 0xd6, 0x87, 0x8}, 0x58d68708, "a"},
	{[]byte{0xfb, 0xb3, 0xa8, 0xdf}, 0xfbb3a8df, "ab"},
	{[]byte{0xe, 0x39, 0x76, 0x31}, 0x0e397631, "abc"},
	{[]byte{0x49, 0x6f, 0x81, 0x9a}, 0x496f819a, "sK2iisPVTchSsRXIBTPUSCWswVsWVB0s9Qsve"},
	{[]byte{0xb0, 0x83, 0xcc, 0xe3}, 0xb083cce3, "J4b58TgCOdroAvWzHN1HFZQQ"},
	{[]byte{0xce, 0x4f, 0xb, 0xb5}, 0xce4f0bb5, "LbycZRyoRYqYtw9dzyBOuvQQByaOUcY"},
	{[]byte{0xde, 0xad, 0xbe, 0xef}, 0xdeadbeef, ""},
	{[]byte{0x93, 0x10, 0x42, 0x49}, 0x93104249, "Sy2ZzcNt6avMfdQo4e2pQTjGs4hfAi7rQo"},
	{[]byte{0x31, 0x1d, 0x95, 0xff}, 0x311d95ff, "DmsUiSW65STrO9MYz9UZEiHoA9W"},
	{[]byte{0xdc, 0xf0, 0xab, 0xfa}, 0xdcf0abfa, "RL5"},
	{[]byte{0x33, 0xea, 0xc7, 0xd8}, 0x33eac7d8, "67"},
	{[]byte{0x8, 0x5d, 0x88, 0x1a}, 0x085d881a, "NJz02SkBRGkGn9d0nztLLSL9g8YW3p4d7xAfgB"},
	{[]byte{0xaa, 0xbe, 0x2, 0xcb}, 0xaabe02cb, "C"},
	{[]byte{0xba, 0xdd, 0xeb, 0xe8}, 0xbaddebe8, "6V0CbxRjAuvTgONMsMM4f"},
	{[]byte{0x7d, 0xe6, 0x5c, 0xf8}, 0x7de65cf8, "UpAx2XrCe23Dupo4aePyuUFyIJMQTg"},
	{[]byte{0xa6, 0xed, 0x36, 0x3d}, 0xa6ed363d, "yDVs38VovVv7qUbzOSzvSbbIwdeW4er"},
	{[]byte{0x65, 0x72, 0xe6, 0x3c}, 0x6572e63c, "qfFZyU"},
	{[]byte{0x2b, 0xd4, 0x56, 0x51}, 0x2bd45651, "5Em2SulDbzArw6j"},
	{[]byte{0x3b, 0x8e, 0x14, 0x3e}, 0x3b8e143e, "kkscBEhp"},
	{[]byte{0x49, 0x2f, 0xc4, 0x2}, 0x492fc402, "Zg5yRgd6dsnz02zPeSi6a4PjaRzD8Qdgo"},
	{[]byte{0x4c, 0xd5, 0x61, 0x37}, 0x4cd56137, "uSHMkV6Fvhcaald2j2RdYU96ctq"},
	{[]byte{0xa2, 0x57, 0x4d, 0xb}, 0xa2574d0b, "7BakZCTxLR"},
	{[]byte{0xb6, 0xbd, 0x8e, 0x51}, 0xb6bd8e51, "URvZqDQRaPZMy3Fpi5nz"},
	{[]byte{0x34, 0x55, 0x69, 0x3c}, 0x3455693c, "M5qKA3vUAmOJ17wIeBa0c4U6iwuAaxRF8L"},
	{[]byte{0x93, 0x6d, 0x8f, 0x36}, 0x936d8f36, "vvGwVWK2QDZRePcPhbEAZeNm6AB3oP0TCb"},
	{[]byte{0x54, 0x95, 0xf1, 0x16}, 0x5495f116, "IJZpZ2tJ4SaqNEz25oV6ceBxSCX4lqF8ElmwXfw"},
	{[]byte{0x98, 0x47, 0x30, 0x79}, 0x98473079, "7LdX6NWCjkTeQbTYS4S2rzMrbNFPleXbGWeSQt"},
	{[]byte{0x4b, 0x75, 0x27, 0x17}, 0x4b752717, "9rbidzBNqzuqazhmkQENPnWrhJrxHiUQP"},
	{[]byte{0x5f, 0x9d, 0xfd, 0xe8}, 0x5f9dfde8, "qjXQN28P42FmdNaHl6iQLFcKT"},
	{[]byte{0x46, 0x7a, 0xe8, 0x8e}, 0x467ae88e, "Q47POeCdVhRZjTX0"},
	{[]byte{0xa4, 0x12, 0x6b, 0xd}, 0xa4126b0d, "UbyJd5VDvCaoKBJzdz7yE824h1dsAT4MpdZ"},
	{[]byte{0xd9, 0xc5, 0xbe, 0xf7}, 0xd9c5bef7, "qE4P"},
	{[]byte{0x47, 0x23, 0xcc, 0xec}, 0x4723ccec, "t2062iRqkiOEc65V7GMtIbAHt"},
	{[]byte{0xde, 0xad, 0xbe, 0xef}, 0xdeadbeef, ""},
	{[]byte{0xb5, 0xda, 0xa2, 0x1a}, 0xb5daa21a, "7bTduA"},
}

func TestGolden64(t *testing.T) {
	hash := HashLittle2()
	require.Equal(t, 8, hash.Size())
	require.Equal(t, 1, hash.BlockSize())

	for _, g := range golden32 {
		hash.Reset()
		done, err := hash.Write([]byte(g.text))
		require.NoError(t, err)
		if done != len(g.text) {
			t.Fatalf("wrote only %d out of %d bytes", done, len(g.text))
		}
		if actual := hash.Sum(nil); !bytes.Equal(g.sum, actual[:4]) {
			t.Errorf("hashlittle2(%q) = 0x%x want 0x%x", g.text, actual, g.sum)
		}

		hash.Reset()
		done, err = hash.Write([]byte(g.text))
		if err != nil {
			t.Fatalf("write error: %s", err)
		}
		if done != len(g.text) {
			t.Fatalf("wrote only %d out of %d bytes", done, len(g.text))
		}

		if actual := hash.Sum64(); actual>>32 != g.u64 {
			t.Errorf("hashlittle(%q) = 0x%x want 0x%x", g.text, actual, g.u64)
		}
	}
}
