# 🚀 CLEAN_IP_FINDER – اسکنر حرفه‌ای آی‌پی تمیز
----
  
 **#Free_Iran**

---

![IRAN Flag](https://github.com/mobin12a1/CLEAN_IP_FINDER/blob/main/Iran%20flag.svg.png)


## 📌 این ابزار چیکار میکنه؟

این اسکریپت بهت کمک می‌کنه تا **آی‌پی‌های تمیز** (Clean IP) برای کانفیگ‌های **Xray, V2Ray, Sing‑box و تانل WebSocket** پیدا کنی.

✅ پینگ واقعی (TCP latency) را اندازه می‌گیره  
✅ تست TLS handshake (برای پورت‌های HTTPS)  
✅ تست HTTP TTFB و WebSocket upgrade  
✅ خروجی گروه‌بندی شده بر اساس پورت، مرتب شده بر اساس latency  
✅ مقاوم در برابر کرش (همه نتایج لحظه‌ای در raw_results.txt ذخیره می‌شن)  
✅ مصرف حافظه بهینه (مناسب برای رنج‌های میلیونی)

---

## 📥 نصب و اجرا

### روی Termux (اندروید)

```bash
pkg update && pkg install python -y
pip install requests
# فایل اسکریپت رو در حافظه ذخیره کن
cd /storage/emulated/0/Download/CLEAN_IP_FINDER[V2.0]/python CLEAN_IP_FINDER.py
```

روی ویندوز

1. پایتون 3.7+ رو از python.org نصب کن (تیک Add to PATH رو بزن)
2. خط فرمان رو باز کن:

```cmd
pip install requests
cd CLEAN_IP_FINDER[V2.0]
python CLEAN_IP_FINDER.py
```

---

🧠 چطور استفاده کنم؟

بعد از اجرا، سوالاتی می‌پرسه. بیشترشون رو می‌تونی با Enter رد کنی (مقدار پیش‌فرض خوبه). فقط کافیه آدرس هدف رو بدی.

مثال ورودی ساده:

```text
IP/Range/Domain: 104.16.24.0/24
Ports (empty for defaults): 
TCP timeout (ms) [800]: 
Enabled HTTP Test? (y/n) [y]: 
...
```

مثال خروجی results.txt:

```text
--- Port 80 ---
104.16.24.1          TCP=12.3ms HTTP=88.1ms -> TCP+HTTP
104.16.24.2          TCP=15.0ms HTTP=Timeout -> HTTP_TIMEOUT

--- Port 443 ---
104.16.24.1          TCP=14.5ms TLS=45.2ms HTTP=117.2ms -> TCP+HTTP+TLS
104.16.24.2          TCP=16.0ms TLS=Failed -> TLS_FAIL
```

---

📊 معنی وضعیت‌ها

وضعیت معنی
TCP فقط اتصال TCP موفق (تست لایه بالاتر نشده)
TCP+HTTP TCP موفق + پاسخ HTTP موفق
TCP+TLS TCP موفق + دست دادن TLS موفق
TCP+HTTP+TLS هر سه موفق
WS WebSocket بدون TLS موفق
WS_TLS WebSocket با TLS موفق
HTTP_TIMEOUT TCP موفق، درخواست HTTP تایم‌اوت خورده
HTTP_FAIL TCP موفق، خطا در درخواست HTTP
TLS_TIMEOUT TCP موفق، دست دادن TLS تایم‌اوت خورده
TLS_FAIL TCP موفق، خطا در دست دادن TLS

---

🔧 نکات کلیدی برای بهترین نتیجه

· بهترین آی‌پی‌ها رو بر اساس کمترین TCP=...ms انتخاب کن.
· اگه WebSocket می‌خوای، گزینه Enabled WebSocket Test? رو y بزن و مسیر درست رو وارد کن.
· تعداد کارگرها رو برای سیستم ضعیف (مثل گوشی) کم کن (مثلاً 15 و 20).
· اگه خطای Too many open files دیدی، تعداد کارگرها رو کاهش بده.
· برای خروج از اسکن در هر زمان، Ctrl + C رو بزن. نتایج تا اون لحظه در raw_results.txt ذخیره می‌شن.

---

🛠 مشکلات رایج و راه‌حل

مشکل راه‌حل
ModuleNotFoundError: No module named 'requests' pip install requests رو اجرا کن
اسکن خیلی کند است TCP timeout رو کاهش بده (مثلاً 400) و تعداد کارگرها رو زیاد کن
results.txt خالی است مطمئن شو HTTP test یا TLS test فعال باشه و پورت درست وارد شده باشه
در Termux خطای Permission denied اول termux-setup-storage رو بزن و اجازه دسترسی بده

---

📁 فایل‌های خروجی

· results.txt – خروجی نهایی تمیز (آی‌پی‌های مرده حذف شدن)
· raw_results.txt – پشتیبان خام (در صورت کرش، نتایج اینجا می‌مونه)
· temp_results.txt – موقتی (بعد از اسکن حذف می‌شه)

---

💬 ارتباط با من

این ابزار رو با ❤️ نوشتم. اگه سوال یا پیشنهادی داشتی، خوشحال می‌شم بشنوم.

#Free_Iran
موفق باشی – مبین

</div>
```
