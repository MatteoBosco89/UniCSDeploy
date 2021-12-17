import cloudscraper
from bs4 import BeautifulSoup
import lxml

class Scraper:

    def __init__(self):
        self.feed_url = "https://securityaffairs.co/wordpress/feed"

    def getAllArticles(self):
        scraper = cloudscraper.create_scraper()
        feed = scraper.get(self.feed_url)
        articles_list = []
        if "200" in str(feed):
            soup = BeautifulSoup(feed.text, "lxml")
            articles = soup.findAll("item")

            for art in articles:
                title = art.find("title").text
                description = art.find("description").text
                link = art.findAll("a")[0].get("href")

                data = {
                    "title": title,
                    "description": description,
                    "link": link
                }
                articles_list.append(data)

            return articles_list
        else:
            return None
