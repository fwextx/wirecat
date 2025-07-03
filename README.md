# Wirecat - Real-Time Packet Viewer for Windows

**Wirecat** is a sleek, modern network traffic analyzer built with Python and PyQt5. It lets you monitor incoming and outgoing packets in real time. 

---

## Legal Disclaimer

Wirecat is for **educational and debugging purposes only**.  
Do **not** use it to monitor networks you don’t own or control.

---

## Features

- Real-time packet capture and visualization  
- Expandable bubbles showing raw hex+ASCII packet content  
- Filter packets by direction: All / Sending / Receiving  
- Application name and icon detection  
- Frameless, resizable custom window for Windows  
- Dark mode interface

---

## Installation

> **Windows only. Requires administrator privileges to sniff packets.**

### 1. Clone the repository:
```bash
git clone https://github.com/fwextx/wirecat
cd wirecat
```

### 2. Create a virtual environment (optional but recommended):
```bash
python -m venv wirecat
wirecat\Scripts\activate
```

### 3. Install requirements:
```bash
pip install -r requirements.txt
```

### 4. Run the app:
```bash
python main.py
```

---

## Usage

- **Click bubbles** to expand and see detailed packet contents.  
- **Use filter buttons** (All, Sending, Receiving) to control what’s shown.  
- **Drag the title bar** to move the window.  
