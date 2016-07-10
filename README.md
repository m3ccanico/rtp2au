# rtp2au

Extracts G711 from an IP multicast RTP stream and writes it into an .au file.

The script will compress any silence (missing RTP packets) that is longer than 3 seconds to 3 seconds.

## Usage

Edit the Python file and adjust the variable in the top to your requirements. Then just run the script with Python:

```Bash
python rtp2au.py
```
