# GHSA-6R28-9PPF-4HJ5

repo: gopacket/gopacket

summary: GoPacket's Diameter AVP decoder: uint32 underflow on vendor header size leads to unbounded ~4 GiB allocation (unauthenticated remote DoS)

aliases: ['CVE-2026-54345']

severity: MODERATE

evidence: file_history blamed_lines=0 files=['layers/diameter_avp_decoders.go', 'layers/diameter_test.go']

intro: fe11a243b3365bf877ddd91f9ba37206c25d96df

intro_subject: Diameter protocol parsing support (#140)

intro_date: 2025-11-03T02:23:04+01:00

fix: 145859d0eaee1a6f5925ffb93851c976449c3311

affected: [
  {
    "package": {
      "ecosystem": "Go",
      "name": "github.com/gopacket/gopacket"
    },
    "ranges": [
      {
        "type": "ECOSYSTEM",
        "events": [
          {
            "introduced": "0"
          },
          {
            "fixed": "1.6.1"
          }
        ]
      }
    ],
    "database_specific": {
      "last_known_affected_version_range": "<= 1.6.0"
    }
  }
]

DETAILS:
## Summary

The Diameter AVP decoder in `github.com/gopacket/gopacket` computes `dataLength := avp.Length - uint32(headerSize)` without first ensuring `avp.Length >= headerSize`. When the Vendor flag is set, `headerSize` is 12, but the only length guard upstream rejects `avp.Length < 8`. An AVP with the Vendor flag set and a 24-bit Length field of 8, 9, 10, or 11 therefore underflows the `uint32` subtraction to ~4,294,967,292, which is passed straight to `make([]byte, dataLength)`. A single 32-byte Diameter message forces a ~4 GiB allocation; a short burst of such messages exhausts memory and OOM-kills memory-constrained collectors. This is an unauthenticated remote denial of service (CWE-191 integer underflow -> CWE-770 unbounded allocation).

## Root cause (file:line @ v1.6.0)

`layers/diameter_avp_decoders.go`, `decodeDiameterAVP`:

```go
avp.Length = uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7]) // 24-bit wire value

if avp.Length < 8 {                       // only rejects < 8
    return DiameterAVP{}, 0, fmt.Errorf("invalid AVP length: %d", avp.Length)
}

headerSize := 8
dataOffset := 8
if avp.Flags.Vendor {                     // Vendor flag = wire bit data[4] & 0x80
    if len(data) < 12 { ... }
    avp.VendorID = binary.BigEndian.Uint32(data[8:12])
    headerSize = 12                       // header is now 12, but only >= 8 was checked
    dataOffset = 12
}

paddedLength := avp.Length                // equals avp.Length; for avp.Length <= 12
if avp.Length%4 != 0 { paddedLength = avp.Length + (4 - avp.Length%4) }
if uint32(len(data)) < paddedLength {     // only requires ~12 bytes present
    return DiameterAVP{}, 0, fmt.Errorf("AVP data truncated: ...")
}

dataLength := avp.Length - uint32(headerSize)  // 8 - 12 = uint32 underflow = 4294967292
avp.Data = make([]byte, dataLength)            // make([]byte, ~4.29e9) ~= 4 GiB
copy(avp.Data, data[dataOffset:dataOffset+int(dataLength)])  // out-of-bounds slice -> panic
```

For `avp.Length` in `{8, 9, 10, 11}` with the Vendor flag set: the `avp.Length < 8` guard passes, `paddedLength == avp.Length` so only `avp.Length` bytes must be present, and `dataLength = avp.Length - 12` underflows the `uint32`. The allocation size is determined entirely by the attacker-supplied 3-byte Length field plus a single flag bit. The `make` executes before the `copy`, so the multi-gigabyte allocation is requested regardless of whether the copy later panics.

## Reachability (remote attacker -> sink)

`LayerTy

REFS:
- WEB https://github.com/gopacket/gopacket/security/advisories/GHSA-6r28-9ppf-4hj5
- WEB https://github.com/gopacket/gopacket/commit/145859d0eaee1a6f5925ffb93851c976449c3311
- PACKAGE https://github.com/gopacket/gopacket
- WEB https://github.com/gopacket/gopacket/releases/tag/v1.6.1

INTRO_LOG:
fe11a243b3365bf877ddd91f9ba37206c25d96df
Phil <dreadl0ck@protonmail.ch>
2025-11-03T14:23:04+13:00
Diameter protocol parsing support (#140)

* feat: add diameter layer type

* feat: update port mappings for diameter and sip

* feat: add diameter as sctp payload protocol

* feat: diameter decoder

* feat: diameter avp decoder

* feat: diameter avp codes

* feat: diameter decoding tests

* Update layers/ports.go

Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>

---------

Co-authored-by: Ali <10158936+mosajjal@users.noreply.github.com>
Co-authored-by: Copilot <175728472+Copilot@users.noreply.github.com>


INTRO_STAT:
 layers/diameter.go              | 395 +++++++++++++++++++++++++++++++
 layers/diameter_avp_codes.go    | 204 ++++++++++++++++
 layers/diameter_avp_decoders.go | 152 ++++++++++++
 layers/diameter_test.go         | 509 ++++++++++++++++++++++++++++++++++++++++
 layers/layertypes.go            |   1 +
 layers/ports.go                 |  47 +++-
 layers/sctp.go                  |  10 +
 7 files changed, 1317 insertions(+), 1 deletion(-)


INTRO_DIFF_OVERLAP:
diff --git a/layers/diameter_avp_decoders.go b/layers/diameter_avp_decoders.go
new file mode 100644
index 0000000..40b2443
--- /dev/null
+++ b/layers/diameter_avp_decoders.go
@@ -0,0 +1,152 @@
+package layers
+
+import (
+	"encoding/binary"
+	"errors"
+	"fmt"
+)
+
+// decodeDiameterAVP decodes a single AVP and returns it along with bytes consumed
+func decodeDiameterAVP(data []byte) (DiameterAVP, int, error) {
+	if len(data) < 8 {
+		return DiameterAVP{}, 0, errors.New("AVP too short")
+	}
+
+	avp := DiameterAVP{}
+
+	// AVP Code (bytes 0-3)
+	avp.Code = binary.BigEndian.Uint32(data[0:4])
+
+	// AVP Flags (byte 4)
+	avp.Flags.Vendor = (data[4] & 0x80) != 0
+	avp.Flags.Mandatory = (data[4] & 0x40) != 0
+	avp.Flags.Protected = (data[4] & 0x20) != 0
+
+	// AVP Length is 24 bits (bytes 5-7)
+	avp.Length = uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
+
+	if avp.Length < 8 {
+		return DiameterAVP{}, 0, fmt.Errorf("invalid AVP length: %d", avp.Length)
+	}
+
+	headerSize := 8
+	dataOffset := 8
+
+	// Vendor ID (optional, present if Vendor flag is set)
+	if avp.Flags.Vendor {
+		if len(data) < 12 {
+			return DiameterAVP{}, 0, errors.New("AVP with vendor flag too short")
+		}
+		avp.VendorID = binary.BigEndian.Uint32(data[8:12])
+		headerSize = 12
+		dataOffset = 12
+	}
+
+	// Calculate padding (AVPs are padded to 4-byte boundaries)
+	paddedLength := avp.Length
+	if avp.Length%4 != 0 {
+		paddedLength = avp.Length + (4 - avp.Length%4)
+	}
+
+	if uint32(len(data)) < paddedLength {
+		return DiameterAVP{}, 0, fmt.Errorf("AVP data truncated: expected %d bytes, got %d", paddedLength, len(data))
+	}
+
+	// Extract AVP data
+	dataLength := avp.Length - uint32(headerSize)
+	avp.Data = make([]byte, dataLength)
+	copy(avp.Data, data[dataOffset:dataOffset+int(dataLength)])
+
+	// Check if this is a Grouped AVP and decode sub-AVPs
+	// Use vendor-aware type detection
+	if avpType, ok := GetDiameterAVPType(avp.Code, avp.VendorID); ok && avpType == DiameterAVPTypeGrouped {
+		avp.GroupedAVPs = []DiameterAVP{}
+		subAVPData := avp.Data
+		for len(subAVPData) >= 8 {
+			subAVP, consumed, err := decodeDiameterAVP(subAVPData)
+			if err != nil {
+				break
+			}
+			avp.GroupedAVPs = append(avp.GroupedAVPs, subAVP)
+			subAVPData = subAVPData[consumed:]
+		}
+	}
+
+	return avp, int(paddedLength), nil
+}
+
+// ParseDiameterAVPs parses all AVPs from a data slice
+func ParseDiameterAVPs(data []byte) ([]DiameterAVP, error) {
+	avps := []DiameterAVP{}
+
+	for len(data) >= 8 {
+		avp, bytesConsumed, err := decodeDiameterAVP(data)
+		if err != nil {
+			return avps, err
+		}
+		avps = append(avps, avp)
+		data = data[bytesConsumed:]
+	}
+
+	return avps, nil
+}
+
+// SerializeDiameterAVP serializes a Diameter AVP to bytes
+func SerializeDiameterAVP(avp *DiameterAVP) []byte {
+	headerSize := 8
+	if avp.Flags.Vendor {
+		headerSize = 12
+	}
+
+	length := headerSize + len(avp.Data)
+	paddedLength := length
+	if length%4 != 0 {
+		paddedLength = length + (4 - length%4)
+	}
+
+	bytes := make([]byte, paddedLength)
+
+	// AVP Code
+	binary.BigEndian.PutUint32(bytes[0:4], avp.Code)
+
+	// AVP Flags
+	bytes[4] = 0
+	if avp.Flags.Vendor {
+		bytes[4] |= 0x80
+	}
+	if avp.Flags.Mandatory {
+		bytes[4] |= 0x40
+	}
+	if avp.Flags.Protected {
+		bytes[4] |= 0x20
+	}
+
+	// AVP Length (24 bits)
+	bytes[5] = byte(length >> 16)
+	bytes[6] = byte(length >> 8)
+	bytes[7] = byte(length)
+
+	// Vendor ID (if present)
+	if avp.Flags.Vendor {
+		binary.BigEndian.PutUint32(bytes[8:12], avp.VendorID)
+		copy(bytes[12:], avp.Data)
+	} else {
+		copy(bytes[8:], avp.Data)
+	}
+
+	return bytes
+}
+
+// SerializedAVPLength returns the length of the AVP when serialized
+func SerializedAVPLength(avp *DiameterAVP) int {
+	headerSize := 8
+	if avp.Flags.Vendor {
+		headerSize = 12
+	}
+	length := headerSize + len(avp.Data)
+	// Pad to 4-byte boundary
+	if length%4 != 0 {
+		length += 4 - (length % 4)
+	}
+	return length
+}
diff --git a/layers/diameter_test.go b/layers/diameter_te

FIX_LOG:
145859d0eaee1a6f5925ffb93851c976449c3311
tonghuaroot (童话) <tonghuaroot@gmail.com>
2026-06-05T08:43:24+12:00
Merge commit from fork

decodeDiameterAVP computed dataLength = avp.Length - uint32(headerSize)
without first ensuring avp.Length >= headerSize. The only length guard
(avp.Length < 8) uses the non-vendor header size, but when the Vendor
flag is set headerSize is 12. A vendor AVP with a 24-bit Length of 8..11
therefore underflowed the uint32 subtraction to ~4294967292 and was
passed to make([]byte, dataLength), requesting a ~4 GiB allocation from
attacker-controlled input (CWE-191 -> CWE-770).

Add a guard, after headerSize is finalized, that rejects any AVP whose
declared Length cannot cover its own header, mirroring the existing
length check. Add a regression test that feeds underflowing vendor AVPs
(Length 8..11) and asserts they are rejected without an oversized
allocation; the test panics against the unpatched decoder.


FIX_STAT:
 layers/diameter_avp_decoders.go |  9 +++++++
 layers/diameter_test.go         | 59 +++++++++++++++++++++++++++++++++++++++++
 2 files changed, 68 insertions(+)


FIX_DIFF_OVERLAP:
diff --git a/layers/diameter_avp_decoders.go b/layers/diameter_avp_decoders.go
index 40b2443..ce7925e 100644
--- a/layers/diameter_avp_decoders.go
+++ b/layers/diameter_avp_decoders.go
@@ -52,6 +52,15 @@ func decodeDiameterAVP(data []byte) (DiameterAVP, int, error) {
 		return DiameterAVP{}, 0, fmt.Errorf("AVP data truncated: expected %d bytes, got %d", paddedLength, len(data))
 	}
 
+	// Reject an AVP whose declared Length cannot cover its own header. The
+	// earlier "avp.Length < 8" check uses the non-vendor header size, but when
+	// the Vendor flag is set headerSize is 12, so a Length of 8..11 would make
+	// the dataLength subtraction below underflow the uint32 and request a
+	// multi-gigabyte allocation.
+	if avp.Length < uint32(headerSize) {
+		return DiameterAVP{}, 0, fmt.Errorf("invalid AVP length: %d, smaller than header size %d", avp.Length, headerSize)
+	}
+
 	// Extract AVP data
 	dataLength := avp.Length - uint32(headerSize)
 	avp.Data = make([]byte, dataLength)
diff --git a/layers/diameter_test.go b/layers/diameter_test.go
index f74518b..4322865 100644
--- a/layers/diameter_test.go
+++ b/layers/diameter_test.go
@@ -484,6 +484,65 @@ func TestDiameter3GPPVendorAVP(t *testing.T) {
 	}
 }
 
+// TestDiameterVendorAVPLengthUnderflow checks that a vendor AVP whose declared
+// 24-bit Length (8..11) is smaller than the 12-byte vendor header is rejected
+// before the dataLength subtraction, rather than underflowing the uint32 and
+// requesting a ~4 GiB allocation in make([]byte, dataLength). The AVP loop in
+// DecodeFromBytes stops at the first undecodable AVP, so the observable effect
+// of the fix is that the malicious AVP is dropped (no oversized Data buffer is
+// ever allocated) instead of the decoder attempting the huge make.
+func TestDiameterVendorAVPLengthUnderflow(t *testing.T) {
+	for _, avpLen := range []byte{0x08, 0x09, 0x0a, 0x0b} {
+		// 20-byte Diameter base header + a 12-byte vendor AVP whose Length
+		// field is avpLen (< 12). Total message length is 32 bytes.
+		data := []byte{
+			0x01, 0x00, 0x00, 0x20, // Version, Length (32)
+			0x80, 0x00, 0x01, 0x01, // Flags: Request, Command Code (257)
+			0x00, 0x00, 0x00, 0x00, // Application ID
+			0x00, 0x00, 0x00, 0x01, // Hop-by-Hop ID
+			0x00, 0x00, 0x00, 0x01, // End-to-End ID
+			// Vendor AVP
+			0x00, 0x00, 0x00, 0x01, // AVP Code: 1
+			0x80, 0x00, 0x00, avpLen, // Flags: Vendor, Length: avpLen (< 12)
+			0x00, 0x00, 0x00, 0x00, // Vendor ID
+		}
+
+		// The decoder must reject this AVP. The whole message decodes without
+		// crashing and yields no AVPs; in particular no AVP carries a buffer
+		// larger than the input (which is what the underflow would produce).
+		layer := &Diameter{}
+		if err := layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
+			t.Fatalf("avpLen=%d: unexpected message-level decode error: %v", avpLen, err)
+		}
+		if len(layer.AVPs) != 0 {
+			t.Errorf("avpLen=%d: expected the underflowing vendor AVP to be rejected (0 AVPs), got %d", avpLen, len(layer.AVPs))
+		}
+		for _, avp := range layer.AVPs {
+			if len(avp.Data) > len(data) {
+				t.Errorf("avpLen=%d: AVP Data length %d exceeds input length %d (underflow not rejected)", avpLen, len(avp.Data), len(data))
+			}
+		}
+
+		// The recovering NewPacket path must also stay alive and not panic.
+		_ = gopacket.NewPacket(data, LayerTypeDiameter, gopacket.Default)
+	}
+
+	// Direct unit check on the decoder: an underflowing vendor AVP returns a
+	// non-nil error and never an oversized Data buffer.
+	rawAVP := []byte{
+		0x00, 0x00, 0x00, 0x01, // AVP Code: 1
+		0x80, 0x00, 0x00, 0x08, // Flags: Vendor, Length: 8 (< 12 vendor header)
+		0x00, 0x00, 0x00, 0x00, // Vendor ID
+	}
+	avp, _, err := decodeDiameterAVP(rawAVP)
+	if err == nil {
+		t.Fatalf("decodeDiameterAVP: expected an error for vendor AVP with Length 8 < header size 12, got nil")
+	}
+	if len(avp.Data) > len(rawAVP) {
+		t.Errorf("decodeDiameterAVP: returned Data length %d exceeds input le

intro_is_ancestor_of_fix: True

tags_contain_intro_sample: []

tags_contain_fix_sample: []

tags_with_intro_not_fix_sample: []