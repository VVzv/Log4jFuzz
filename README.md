# Log4jFuzz
log4j vuln fuzz/scan

## USE
```
// it's use localhost udp server to check target vuln.
python3 log4jFuzz.py [option]
optional arguments:
  -u URL, --url URL     Target URL. (e.g. http://example.com )
  -f FILE, --file FILE  Select a target list file. (e.g. list.txt )
  -v, --verbosity       Show fuzz info.
  --bypass              Use bypass waf payload. (Default False)
```
```
// bypass waf payload
python3 log4jFuzz.py -u "http://192.168.0.150:16787/" --bypass
```
![image](https://user-images.githubusercontent.com/42025843/146722124-01e2eba2-cde4-47f7-a741-973bf1e8f80f.png)
```
// read file to fuzzing
python3 log4jFuzz.py -f url.txt
```
![image](https://user-images.githubusercontent.com/42025843/146722227-a1d061d6-b3f8-433c-ac55-91bd70d6bcc4.png)

# 免责声明
本工具主要用于企业自查内网log4j漏洞，未经授权允许，不得善自使用本工具进行任何攻击活动，由于传播、利用此工具所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。
