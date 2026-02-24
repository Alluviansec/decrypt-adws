# decrypt-adws

Decrypt ADWS (Active Directory Web Services) .NET Message Security traffic from pcap captures using a Kerberos keytab.

For the full technical writeup, see: **[Decrypting ADWS Traffic: Peeling Back the Layers of .NET Message Security](https://alluvian.org/posts/2026/02/decrypting-adws-traffic/)**

## What it does

ADWS traffic (port 9389) is wrapped in 7 layers of encoding and encryption. Even with a valid keytab, Wireshark's built-in dissectors won't decrypt it. This script peels back every layer:

```
TCP > .NET Message Framing > NegotiateStream (SPNEGO/Kerberos) > GSS-Wrap CFX
    > Inner NMF Sized Envelopes > MC-NBFS Session Dictionary > MC-NBFX Binary XML
```

The output is readable SOAP/XML containing the full AD enumeration queries and responses, with `nTSecurityDescriptor` ACLs automatically decoded from base64 binary to SDDL.

## Features

- **Pcap/pcapng auto-detection** with IPv4 and IPv6 support
- **MIT keytab v2 parsing** - tries all key entries against ticket enctypes
- **TCP reassembly** with retransmission dedup and gap detection
- **ADWS port auto-detection** from NMF preambles
- **Full MC-NBFX Binary XML decoding** using the correct .NET runtime text record mapping (not the inaccurate MC-NBFX open specification)
- **nTSecurityDescriptor > SDDL** - pure Python security descriptor parser with:
  - Domain SID auto-detection
  - Well-known SID abbreviation (DA, BA, SY, EA, etc.)
  - Object ACE GUID parsing with 60+ AD extended rights/property set lookups
  - Access mask decomposition to SDDL rights strings

## Requirements

```
pip install dpkt minikerberos pycryptodome
```

## Usage

```bash
python decrypt_adws.py <pcap_file> <keytab_file> [--port PORT]
```

### Example

```bash
python decrypt_adws.py "extrahop 2026-02-03 16.44.10 to 17.14.10 AEDT.pcapng" dc01.keytab
```

### Output

- `decrypted_adws.xml` - All decoded SOAP messages with SDDL annotations
- `decrypted_adws_raw.bin` - Raw decrypted binary streams
- `decrypted_raw/` - Individual stream files per connection/direction

### Sample output

```xml
<!-- SDDL: O:DAG:DAD:PAI(A;;RPWPCCDCLCSWRCWDWOGA;;;WD)(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;DA) -->
```

## Included sample data

- `dc01.keytab` - Kerberos keytab for the lab domain controller (AES-256, kvno 4)
- `extrahop 2026-02-03 16.44.10 to 17.14.10 AEDT.pcapng` - SOAPHound ADWS capture from an ExtraHop sensor

## License

MIT
