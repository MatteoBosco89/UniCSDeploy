import cloudscraper
from bs4 import BeautifulSoup
import lxml
from datetime import datetime
from email.utils import parsedate_tz, mktime_tz

class Scraper:

    def __init__(self):
        self.feed_url = "https://securityaffairs.co/wordpress/feed"

    def getAllArticles(self):
        scraper = cloudscraper.create_scraper()
        feed = scraper.get(self.feed_url)
        articles_list = []
        if "200" in str(feed):
            soup = BeautifulSoup(feed.text, "html.parser")
            articles = soup.findAll("item")
            for art in articles:
                title = art.find("title").text
                creator = art.find("dc:creator").text
                creator = creator.replace("<![CDATA[", "")
                creator = creator.replace("]]>", "")
                description = BeautifulSoup(art.find("description").text, "html.parser")
                link = description.findAll("p")[1].find("a").get("href")
                description = description.text.replace("<![CDATA[", " ")
                description = description.replace("]]>", " ")
                pubdate = art.find("pubdate").text.replace("+0000", "")
                #Fri, 17 Dec 2021 07:38:21
                timestamp = mktime_tz(parsedate_tz(pubdate))
                pubdate = datetime.utcfromtimestamp(timestamp)
                #pubdate = datetime.strptime(pubdate, "%a, %d %b %Y %H:%M:%S ")
                categories = art.findAll("category")
                cats = []
                for c in categories:
                    c = c.text.replace("<![CDATA", "")
                    c = c.replace("]]>", "")
                    cats.append(c)
                data = {
                    "title": title,
                    "description": description,
                    "link": link,
                    "pubdate" : pubdate,
                    "labels" : cats,
                    "creator" : creator
                }
                articles_list.append(data)
            return articles_list
        else:
            return None
