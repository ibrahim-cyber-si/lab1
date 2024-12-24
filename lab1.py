'''
192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020
'''

# Regex-dən istifadə edərək verilmiş veb server log faylından 
# IP ünvanlarını, tarixləri və HTTP metodlarını çıxarın.

import re
import json

ugursuz_cehdler = []
extracted_data = []

with open(r"D:\AZTU\2024_imtahan_payiz\Python\lab1\server_logs.txt", "r") as log:

    ip = re.compile(r'\d+.\d+.\d+.\d+')
    tarix = re.compile(r'\d\d/\w+/\d\d')
    http_method = re.compile(r'\w+ ')

    t = 1

    for line in log.readlines():

        numune_ip = re.findall(ip, line)
        numune_tarix = re.findall(tarix, line)
        numune_http = re.findall(http_method, line)

        print(f"{t})")

        extracted_data.append({"ip":numune_ip[0], "date":numune_tarix[0], "metod":numune_http[2]})

        print("IP:", numune_ip[0], "\nTarix:", numune_tarix[0], "\nHTTP metodu:", numune_http[2])

        t += 1

        if (numune_http[4] != '200 '):
            
            ugursuz_cehdler.append(numune_ip[0])

# 5-den cox ugursuz cehdleri saxlamaq ucun siyahi yaradilir
limit = []

for ip in ugursuz_cehdler:
    if ugursuz_cehdler.count(ip) > 5:
        if ip not in limit:     # eger hemin ip unvan siyahinin icinde deyilse, onda append edilir.
            limit.append(ip)

subheli_ip = {ip: ugursuz_cehdler.count(ip) for ip in limit}

# JSON faylına yazmaq
with open(r"D:\AZTU\2024_imtahan_payiz\Python\lab1\suspicious_ips.json", "w") as json_file:
    json.dump(subheli_ip, json_file, indent=4)

# Log analizi mətn faylı
with open(r"D:\AZTU\2024_imtahan_payiz\Python\lab1\log_analysis.txt", "w") as txt_file:
    for ip, count in subheli_ip.items():
        txt_file.write(f"IP: {ip}, Failed Attempts: {count}\n")


# CSV faylı yaratmaq
with open(r"D:\AZTU\2024_imtahan_payiz\Python\lab1\log_analysis.csv", "w", newline="") as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP Unvan", "Tarix", "HTTP Metodu", "Ugursuz cehd"])
    for data in extracted_data:
        ip = data["ip"]
        date = data["date"]
        method = data["method"]
        failed_count = ugursuz_cehdler.get(ip, 0)
        csv_writer.writerow([ip, date, method, failed_count])

print("Bütün məlumatlar emal edildi və fayllara yazıldı.")
