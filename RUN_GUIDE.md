# JA3Print — Step-by-step Windows Run Guide

## 1. Extract the ZIP
Right-click the ZIP and choose **Extract All**.

## 2. Open Command Prompt
Open the extracted project folder, click the address bar, type `cmd`, and press Enter.
Run `dir` and confirm that `main.py`, `requirements.txt`, `ja3print`, `data`, and `tests` are present.

## 3. Create and activate the virtual environment
```bat
py -3.12 -m venv venv312
venv312\Scripts\activate
```

## 4. Install dependencies
```bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -c "import scapy; print(scapy.__version__)"
```
Expected Scapy version: 2.8.0.

## 5. Run tests and help
```bat
python -m unittest discover -s tests -v
python main.py --help
```

## 6. Analyze your own authorized capture
```bat
python main.py "your_capture.pcapng"
python main.py "your_capture.pcapng" --output reports\analysis.html
```

## 7. Compare in Wireshark
Use the display filter `tls.handshake.type == 1` and compare the visible ClientHello count.
Some fragmented messages may be missed because TCP stream reassembly is not implemented.

## Demo outline
1. Show the project and source code.
2. Run unit tests.
3. Show CLI help.
4. Analyze an authorized PCAP.
5. Open the JSON/HTML report.
6. Explain JA3, JA4, allowlist, and why UNKNOWN does not mean malicious.

## Troubleshooting
- `python is not recognized`: use `py -3.12` or reopen Command Prompt.
- `No module named scapy`: activate venv312 and install requirements.
- `Capture file not found`: check the filename or use its full quoted path.
- No ClientHello results: confirm TLS traffic in Wireshark; fragmented handshakes may be missed.

Only analyze traffic you own or are explicitly authorized to inspect. Do not publish PCAPs containing private information.
