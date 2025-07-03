import psutil
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWinExtras import QtWin
import os

def get_process_icon(src_ip, src_port):
    # Find the process ID owning the port (TCP and UDP)
    pid = None
    for conn in psutil.net_connections(kind='inet'):
        if (conn.laddr.ip == src_ip and conn.laddr.port == src_port) and conn.pid:
            pid = conn.pid
            break

    if pid is None:
        return None, "Unknown"

    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        if not os.path.exists(exe_path):
            return None, proc.name()

        icon = QtWin.fromHICON(  # Get icon from exe handle
            QtWin.HICON(
                QtWin.shell32.ExtractIconW(0, exe_path, 0)
            )
        )

        if icon and not icon.isNull():
            pixmap = icon.pixmap(32, 32)
            return pixmap, proc.name()
        else:
            return None, proc.name()

    except Exception as e:
        return None, "Unknown"
