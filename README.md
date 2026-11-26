# JA3Print Advanced — TLS Fingerprinting & PCAP Analysis

**Version:** 2.0.0  
**Author:** Maaz Khan  
**Track:** Network Defense  
**Language:** Python 3.12  
**Primary dependency:** Scapy 2.8.0

JA3Print is an educational, defensive command-line utility that reads an authorized PCAP/PCAPNG capture, extracts TLS ClientHello information that Scapy can decode, calculates JA3 and JA4 fingerprints, compares JA3 MD5 values with a local allowlist, and writes JSON, CSV, or HTML reports.

> **Responsible-use boundary:** Analyze only traffic from your own machine/network or captures for which you have explicit permission. Do not collect other people's traffic.

## Features
- TLS ClientHello discovery in PCAP/PCAPNG files using Scapy.
- JA3 string and MD5 generation with GREASE filtering.
- JA4 TLS-over-TCP fingerprint generation.
- Optional ServerHello extraction for visibility; JA3S is not yet implemented.
- Local JSON allowlist for manually verified JA3 MD5 values.
- JSON, CSV, and HTML reports.
- Per-packet error tolerance and unit tests.

## Requirements
- Windows 10/11, macOS, or Linux.
- Python 3.12 recommended.
- Scapy 2.8.0.
- Wireshark is useful for independently inspecting captures.

## Windows setup
```bat
py -3.12 -m venv venv312
venv312\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run
```bat
python main.py --help
python main.py your_capture.pcapng
python main.py your_capture.pcapng --output reports\run1.json
python main.py your_capture.pcapng --output reports\run1.csv
python main.py your_capture.pcapng --output reports\run1.html
```

## Allowlist
The starter allowlist is empty. Add a fingerprint only after independently verifying it:
```bat
python main.py --allowlist data\allowlist.json --add-known YOUR_VERIFIED_JA3_MD5
```
`KNOWN` means the hash exists in your local allowlist. `UNKNOWN` means it does not. Neither verdict proves that a client is safe or malicious.

## Tests
```bat
python -m unittest discover -s tests -v
```

## Project structure
```text
main.py
requirements.txt
README.md
RUN_GUIDE.md
PRESENTATION.pdf
ja3print/
  __init__.py
  cli.py
  parser.py
  fingerprints.py
  allowlist.py
  reporting.py
data/
tests/
```

## Important technical limitations
1. Scapy packet dissection is used; TCP stream reassembly is not implemented, so fragmented ClientHello messages may be missed.
2. JA4 support is scoped to TLS over TCP ClientHello data; QUIC/DTLS decoding is not implemented.
3. JA3S is not calculated. The optional ServerHello switch only lists ServerHello records.
4. A TLS fingerprint is not a unique identity and can change after software/library updates.
5. An unknown fingerprint is not a malware verdict. Confirm context with other defensive telemetry.

## References
- JA3: https://github.com/salesforce/ja3
- JA4 specification: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
- Scapy TLS API: https://scapy.readthedocs.io/en/latest/api/scapy.layers.tls.handshake.html

Educational project. Analyze only captures you own or are authorized to inspect.
