import os
import yaml
import time
import traceback
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIStix2Utils
from stix2 import Bundle, Report, Vulnerability, Relationship, Identity, Note, ExternalReference
from datetime import datetime
from scrap.Scraper import Scraper
import json
from email.utils import parsedate_tz, mktime_tz


def create_bundle():
    print("CREATE BUNDLE CALLED")
    try:
        scraper = Scraper()
        print("SCRAPER CALLED")
        scraper.scraping()
        print("SCRAPING FINISHED AND FILES CREATED")
        identity = Identity(
            id=OpenCTIStix2Utils.generate_random_stix_id("identity"),
            name="TalosIntelligence"
        )

        #create bundle for zero day vulnerablity
        print("ZERO BUNDLE CALL")
        hand = scraper.zeroDayFileHandler()
        print(hand)
        for line in hand:
            print(line)
            js = scraper.zeroDaySingle(line)
            print(js)
            if(js is None):
                print("Got None on line " + line)
            else:
                j = json.loads(js)
                timestamp = time.mktime(datetime.strptime(j["date"], "%Y-%m-%d %H:%M:%S").timetuple())
                created = datetime.fromtimestamp(timestamp)
                vulnerability = Vulnerability(
                    id = OpenCTIStix2Utils.generate_random_stix_id("vulnerability"),
                    name = j["id"],
                    created = created,
                    description = "zero day vulnerability",
                    labels=["ZeroDay", "Vulnerability"]
                )
                print("OK")
        print("ZERO BUNDLE CALLED")
        #create bundle for discloseds vulnerability
        print("DISCLOSEDS BUNDLE CALL")
        hand = scraper.disclosedsFileHandler()
        for line in hand:
            datas = scraper.disclosedsSingle(line)
            if(datas is None):
                print("Got None on line " + line)
            else:
                data = json.loads(datas)
                timestamp = time.mktime(datetime.strptime(data["date"], "%Y-%m-%d %H:%M:%S").timetuple())
                pubDate = datetime.fromtimestamp(timestamp)
                productUrl = ExternalReference(
                    url = data["product_urls"],
                    source_name = data["product_urls"].split('/')[2],
                    description = "Product urls"
                )
                talosReport = ExternalReference(
                    url = data["report_url"],
                    description = "Talos Intelligence report",
                    source_name = "talosintelligence.com"
                )
                vulnerability = Vulnerability(
                    id = OpenCTIStix2Utils.generate_random_stix_id("vulnerability"),
                    name = data["cve_number"],
                    description = data["short_description"]+"\n"+data["summary"],
                    labels = [
                        data["id"],
                        data["cvss_score"],
                        data["cwe"]
                    ],
                    external_references = [
                        productUrl,
                        talosReport
                    ]
                )
                note = Note(
                    id = OpenCTIStix2Utils.generate_random_stix_id("note"),
                    created = pubDate,
                    content = data["timeline"],
                    abstract = "Timeline"
                )
                report = Report(
                    id = OpenCTIStix2Utils.generate_random_stix_id("report"),
                    report_types = ["vulnerablity"],
                    created_by_ref = identity.id,
                    name = data["id"],
                    published = pubDate,
                    labels=["vulnerability"],
                    object_refs=[vulnerability.id, note.id]
                )
                relationship = Relationship(
                    id = OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                    relationship_type = "related-to",
                    source_ref = vulnerability.id,
                    target_ref = report.id,
                    confidence = 100
                )
                print("ok")
            print("OK")
    except Exception as e:
        print(e)

create_bundle()