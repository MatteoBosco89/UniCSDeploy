from bs4 import BeautifulSoup
import os
import requests
import cloudscraper
from datetime import datetime
import json

class Scraper:
    def __init__(self):
        self.zeroDays = "https://talosintelligence.com/vulnerability_reports#zerodays"
        self.discloseds = "https://talosintelligence.com/vulnerability_reports#disclosed"
        self.repId = "https://talosintelligence.com/reputation_center/email_rep#top-senders-ip"

    def getZeroDayList(self):
        print("ZeroDay init txt")
        try:
            scraper = cloudscraper.create_scraper()
            headers = {'User-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'}
            req = scraper.get(self.zeroDays)
            if "200" in str(req):
                page = req.text
                if(page is not None):
                    soup = BeautifulSoup(page, 'html.parser')
                    #print(page)
                    table = soup.find("table", {"id":"zero-report"})
                    #print(table)
                    if(table is not None):
                        table_trs = table.findAll("tr")
                        #print(table_trs)
                        vuln_ids = []
                        for tr in table_trs:
                            td = tr.find("td")
                            if(td is not None):
                                vuln_ids.append(td.text.strip())
                        file = open("zeroDays.txt", 'w')
                        for id in vuln_ids:
                            file.write(id+"\n")
        except(requests.ConnectionError)as exception:
            print("Connection Error")
        except(requests.Timeout)as exception:
            print("Connection Timeout")
        print("ZeroDay finished")

    def zeroDayFileHandler(self):
        file_list = open("zeroDays.txt", "r")
        return file_list

    def zeroDaySingle(self, line):
        try:
            scraper = cloudscraper.create_scraper()
            boundle_data = []
            req = scraper.get("https://talosintelligence.com/vulnerability_reports/"+line.rstrip("\n"))
            if("200" in str(req)):
                page = req.text
                if(page):
                    soup = BeautifulSoup(page, 'html.parser')
                    date = soup.find("div", {"id":"page_wrapper"}).find("h5", {"class":"date_time"}).text
                    date_time_obj = datetime.strptime(date, '%B %d, %Y')
                    d = {"id":line.rstrip("\n") , "date":str(date_time_obj)}
                    boundle_data.append(d)
                    return json.dumps(boundle_data)
        except(requests.ConnectionError)as exception:
            print("Connection Error")
        except(requests.Timeout)as exception:
            print("Connection Timeout")

    

    def getDiscloseds(self):
        print("Disclosed txt init")
        try:
            scraper = cloudscraper.create_scraper()
            headers = {'User-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'}
            req = scraper.get(self.discloseds)
            if "200" in str(req):
                page = req.text
                if(page is not None):
                    soup = BeautifulSoup(page, 'html.parser')
                    #print(page)
                    table = soup.find("table", {"id":"vul-report"})
                    #print(table)
                    if(table is not None):
                        table_trs = table.findAll("tr")
                        #print(table_trs)
                        vuln_ids = []
                        file = open("discloseds.txt", 'w')
                        for tr in table_trs:
                            td = tr.find("td")
                            if(td is not None):
                                id = td.find("a").text.strip()
                                link = td.find("a").get("href")
                                file.write(id + ", " + "https://talosintelligence.com"+link + "\n")

        except(requests.ConnectionError)as exception:
            print("Connection Error")
        except(requests.Timeout)as exception:
            print("Connection Timeout")
        print("Disclosed txt finished")

    def disclosedsFileHandler(self):
        discl_list = open("discloseds.txt", "r")
        return discl_list

    def disclosedsSingle(self, line):
        print("Disclosed json init")
        try:
            scraper = cloudscraper.create_scraper()
            boundle_data = []
            line = line.rstrip("\n")
            strs = line.split(",")
            req = scraper.get(strs[1])
            if("200" in str(req)):
                page = req.text
                if(page):
                    soup = BeautifulSoup(page, 'html.parser')
                    report_div = soup.find("div", {"class":"col-xs-12 report"})
                    report_id = report_div.find("h3",{"class":"report_id"}).text
                    short_desc = report_div.find("h2").text
                    date = report_div.find("h5", {"class":"date_time"}).text
                    date_time_obj = datetime.strptime(date, '%B %d, %Y')
                    cve_number = report_div.find("p").text
                    data_div = report_div.find("div")
                    summary = data_div.find("h3", {"id":"summary"})
                    if(summary):
                        summary = summary.find_next().text
                    else:
                        summary = "null"

                    tested_version = data_div.find("h3", {"id":"tested-versions"})
                    if(tested_version):
                        tested_version = tested_version.find_next().text
                    else:
                        tested_version = "null"

                    product_urls = data_div.find("h3", {"id":"product-urls"})
                    if(product_urls):
                        product_urls = product_urls.find_next().find("a")
                        if(product_urls):
                            product_urls = product_urls.text
                        else:
                            product_urls = "null"
                    else:
                        product_urls = "null"

                    cvss_score = data_div.find("h3", {"id":"cvssv3-score"})
                    if(cvss_score):
                        cvss_score = cvss_score.find_next().text
                    else:
                        cvss_score = "null"

                    cwe = data_div.find("h3", {"id":"cwe"})
                    if(cwe):
                        cwe = cwe.find_next().text
                    else:
                        cwe = "null"

                    timeline =  data_div.find("h3", {"id":"timeline"})
                    if(timeline):
                        timeline = timeline.find_next().text
                    else:
                        timeline = "null"

                    vendor_response = data_div.find("h3", {"id":"vendor-response"})
                    if(vendor_response):
                        vendor_response = vendor_response.find_next().text
                    else:
                        vendor_response = "null"

                    credit = report_div.findAll("h5")[2]
                    if(credit):
                        credit = credit.find_next().text
                    else:
                        credit = "null"

                    data = {
                        "id" : report_id,
                        "short_description" : short_desc,
                        "date" : str(date_time_obj),
                        "cve_number" : cve_number,
                        "summary" : summary,
                        "tested_version" : tested_version,
                        "product_urls" : product_urls,
                        "cvss_score" : cvss_score,
                        "cwe" : cwe,
                        "timeline" : timeline,
                        "vendor_response" : vendor_response,
                        "credit" : credit,
                        "report_url" : strs[1]
                    }
                    
                    boundle_data.append(data)
                    return json.dumps(boundle_data)

        except(requests.ConnectionError)as exception:
            print("Connection Error")
        except(requests.Timeout)as exception:
            print("Connection Timeout")
        print("Disclosed json finished")

    #This method scrape the reputation ip
    #Currently can't download the information
    def getReputationIp(self):
        try:
            scraper = cloudscraper.create_scraper()
            headers = {'User-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'}
            page = scraper.get(self.repId).text
            if(page is not None):
                soup = BeautifulSoup(page, 'html.parser')
                open("page.txt", 'w').write(page)
                table = soup.find("table", {"id":"sender-by-ip"})
                if(table is not None):
                    table_trs = table.findAll("tr")
                    #print(table_trs)
                    vuln_ids = []
                    file = open("repId.txt", 'w')
                    for tr in table_trs:
                        tds = tr.findAll("td")
                        if(tds):
                            rep = tds[4].find("span").get("class")
                            line = ""
                            if(rep != "rep-Good"):
                                for i in range(0, 2):
                                    s1 = tds[i].find("a").text.split()
                                    s2 = "https://talosintelligence.com" + tds[i].find("a").get('href')
                                    line += s1 + ", " + s2
                                    if(i != 2):
                                        line += ", "
                                    else:
                                        line += "\n"

                                file.write(line)

        except(requests.ConnectionError)as exception:
            print("Connection Error")
        except(requests.Timeout)as exception:
            print("Connection Timeout")

    def scraping(self):
        self.getZeroDayList()
        self.getDiscloseds()