# NetMonitor

Realtime network connection monitor for Windows.  
Shows which process is connecting to which IP address, with country, ISP, and elapsed time.

![NetMonitor Screenshot](screenshot.png)

## Features

- Realtime TCP/UDP connection monitoring (3s interval)
- GeoIP lookup: country flag, country name, ISP (via ip-api.com)
- Group connections by process name (collapsible)
- Elapsed time since first connection detected
- Filter by process name / IP / country code
- Risk country highlight (CN / RU / KP / IR / BY)
- Hide private IP addresses

## Requirements

- Windows 10/11
- Python 3.10+

## Build EXE

Place all files in the same folder, then run:

```
build.bat
```

This will automatically:
1. Install dependencies (`psutil`, `requests`, `pyinstaller`, `pillow`)
2. Generate `netmonitor.ico`
3. Build `dist\NetMonitor.exe`

> Run `NetMonitor.exe` as Administrator for full process visibility.

## Run as Script

```
pip install psutil requests pillow
python net_monitor.py
```

## Files

| File | Description |
|---|---|
| `net_monitor.py` | Main application |
| `make_icon.py` | Icon generator |
| `build.bat` | EXE build script |

## GeoIP

Uses [ip-api.com](http://ip-api.com) free API.  
Results are cached for 5 minutes. No API key required.  
For commercial use, a paid plan is required.

## License

MIT
