#python script 

#feature extraction
import requests
from bs4 import BeautifulSoup
from confusable_homoglyphs import confusables
import requests
import pandas as pd
import os

proxy = 'http://tempuser1:rgukt123@staffnet.rgukt.ac.in:3128'

os.environ['http_proxy'] = proxy 
os.environ['HTTP_PROXY'] = proxy
os.environ['https_proxy'] = proxy
os.environ['HTTPS_PROXY'] = proxy

def whois_info(domain):
    r = requests.get(f"https://www.whois.com/whois/{domain}")
    li = []
    try:
        soup = BeautifulSoup(r.content,"html.parser").find("div",{"class":"whois-data"})
        df_blocks = soup.find_all("div",{"class":"df-block"})
        inner_blocks = df_blocks[0].find_all("div",{"class":"df-row"})
        #print(inner_blocks)
        for block in df_blocks:
            heading = block.find("div",{"class":"df-heading"}).text
            li.append(heading)
        start = 0
        end = 0
        for rows in inner_blocks:
            txt = str(rows.find("div",{"class":"df-label"}).text)
            if(txt=="Registered On:"):
                start = int(str(rows.find("div",{"class":"df-value"}).text).split("-")[0])
            if(txt == "Expires On:"):
                end = int(str(rows.find("div",{"class":"df-value"}).text).split("-")[0])
        li.append(end-start)
        return li
    
    except:
        return li
def domain_info(li):
    if "Domain Information" in li:
        return 0
    return 1
def reg_info(li):
    if "Registrant Contact" in li:
        return 0
    return 1
def admin_info(li):
    if "Administrative Contact" in li:
        return 0
    return 1
def tech_info(li):
    if "Technical Contact" in li:
        return 0
    return 1
def age(li):
    if(len(li)>0 and str(li[-1]).isdigit()):
        if(li[-1]>=1):
            return 0
        return 1
    return 1
def redirect(domain):
    url = f"https://www.{domain}"
    try:
        r = requests.get(url,verify=False,allow_redirects=False)
        dom = r.headers["location"]
        if domain in dom:
            return 0
        else:
            return 1
    except:
        return 1
def check_ssl(domain):
    url = f"https://www.{domain}"
    try:
        r = requests.get(url)
        return 0
    except:
        return 1
        
def checkHomograph(domain):
    b =  bool(confusables.is_dangerous(domain))
    if b:
        return 1
    return 0
    
f = open("leg_data.csv","w")
f.write("domains, domain_info, reg_info, admin_info, tech_info, age, redirect, check_ssl,checkHomograph,isPhish \n")
df = pd.read_csv("legitimate-urls.csv")
for domain in df.Domain:
    d = str(domain).strip()
    string = d
    li = whois_info(str(domain))
    string += ", "+str(domain_info(li))
    string += ", "+str(reg_info(li))
    string += ", "+str(admin_info(li))
    string += ", "+str(tech_info(li))
    string += ", "+str(age(li))
    string += ", "+str(redirect(li))
    string += ", "+str(check_ssl(li))
    string += ", "+str(checkHomograph(d))
    string += ", "+"0"                  
    string +='\n'
                       
    f.write(string)
f.close()
