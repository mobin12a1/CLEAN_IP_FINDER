# 🚀 CLEAN_IP_FINDER – Professional Clean IP Scanner

----

**#Free_Iran**

----

![IRAN Flag](https://github.com/mobin12a1/CLEAN_IP_FINDER/blob/main/Iran%20flag.svg.png)


## 📌 What does this tool do?

This script helps you find **clean IPs** for **Xray, V2Ray, Sing‑box and WebSocket tunnels**.

✅ Measures real TCP ping (latency)  
✅ TLS handshake test (for HTTPS ports)  
✅ HTTP TTFB and WebSocket upgrade test  
✅ Output grouped by port, sorted by latency  
✅ Crash‑resistant (every result saved immediately to raw_results.txt)  
✅ Memory‑efficient (handles millions of IPs)

---

## 📥 Installation & Usage

### On Termux (Android)

```bash
pkg update && pkg install python -y
pip install requests
# Save the script to storage
cd /storage/emulated/0/Download/CLEAN_IP_FINDER[V2.0]/
python CLEAN_IP_FINDER.py
```

On Windows

1. Install Python 3.7+ from python.org (check Add to PATH)
2. Open Command Prompt:

```cmd
pip install requests
cd CLEAN_IP_FINDER[V2.0]
python CLEAN_IP_FINDER.py
```

---

🧠 How to use?

After running, you'll be asked several questions. Most can be answered by just pressing Enter (defaults are good). Just provide the target address.

Simple input example:

```text
IP/Range/Domain: 104.16.24.0/24
Ports (empty for defaults): 
TCP timeout (ms) [800]: 
Enabled HTTP Test? (y/n) [y]: 
...
```

Example results.txt output:

```text
--- Port 80 ---
104.16.24.1          TCP=12.3ms HTTP=88.1ms -> TCP+HTTP
104.16.24.2          TCP=15.0ms HTTP=Timeout -> HTTP_TIMEOUT

--- Port 443 ---
104.16.24.1          TCP=14.5ms TLS=45.2ms HTTP=117.2ms -> TCP+HTTP+TLS
104.16.24.2          TCP=16.0ms TLS=Failed -> TLS_FAIL
```

---

📊 State meanings

State Meaning
TCP TCP connection only (no higher layer test)
TCP+HTTP TCP + successful HTTP response
TCP+TLS TCP + successful TLS handshake
TCP+HTTP+TLS All three successful
WS WebSocket (no TLS)
WS_TLS WebSocket over TLS
HTTP_TIMEOUT TCP ok, HTTP request timed out
HTTP_FAIL TCP ok, HTTP request failed (closed or invalid response)
TLS_TIMEOUT TCP ok, TLS handshake timed out
TLS_FAIL TCP ok, TLS handshake failed

---

🔧 Tips for best results

· Choose the lowest TCP=...ms as the best IPs.
· If you need WebSocket, set Enabled WebSocket Test? to y and provide the correct path.
· Worker settings: On weak devices (phones), lower them (e.g., 15 and 20).
· If you see Too many open files, reduce the number of workers.
· To stop scanning at any time, press Ctrl + C. Results up to that point are saved in raw_results.txt.

---

🛠 Common issues & solutions

Issue Solution
ModuleNotFoundError: No module named 'requests' Run pip install requests
Scan is very slow Reduce TCP timeout (e.g., 400) and increase workers
results.txt is empty Make sure HTTP test or TLS test is enabled and port is correct
Permission denied in Termux First run termux-setup-storage and allow access

---

📁 Output files

· results.txt – Clean final output (dead IPs removed)
· raw_results.txt – Raw backup (survives crashes)
· temp_results.txt – Temporary (deleted after scan)

---

💬 Contact

This tool was made with ❤️. Feel free to reach out if you have questions or suggestions.

#Free_Iran
Good luck – Mobin

```