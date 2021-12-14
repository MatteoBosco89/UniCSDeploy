import os
import yaml
import time
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIStix2Utils
from stix2 import Bundle, Report, Vulnerability, Relationship, Identity, Note, ExternalReference
from datetime import datetime
from email.utils import parsedate_tz, mktime_tz
import cloudscraper
import xmltodict
from Scraper import Scraper
import json

class TemplateConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.talos_interval = get_config_variable(
            "TALOS_INTERVAL", ["talos", "interval"], config, True
        )

    def get_interval(self) -> int:
        return int(self.talos_interval) / 60 / 60 * 24

    def create_bundle(self, work_id):
        scraper = Scraper()
        scraper.scraping()
        identity = Identity(
            id=OpenCTIStix2Utils.generate_random_stix_id("identity"),
            name="TalosIntelligence"
        )
        if(not os.path.isfile("Scraper/zerosData.json")):
            return 0
        zeroData = open("Scraper/zerosData.json", 'r')
        zerosJson = json.load(zeroData)

        if(not os.path.isfile("Scraper/diclosedsData.json")):
            return 0
        disclosedData = open("Scraper/diclosedsData.json", 'r')
        disclosedsJson = json.load(disclosedData)

        #create bundle for zero day vulnerablity
        if(zerosJson):
            for data in zerosJson:
                created = datetime.strptime(data["date"], '%y-%m-%d')
                vulnerability = Vulnerability(
                    id = OpenCTIStix2Utils.generate_random_stix_id("vulnerability"),
                    name = data["id"],
                    created = created,
                    description = "zero day vulnerability"
                )
                bundle = Bundle(
                    objects = [
                        identity,
                        vulnerability
                    ],
                    allow_custom = True,
                    entities_types = self.helper.connect_scope,
                    work_id = work_id
                ).serialize()
                self.helper.send_stix2_bundle(bundle)

        #create bundle for discloseds vulnerability
        if(disclosedsJson):
            for data in disclosedsJson:
                pubDate = datetime.strptime(data["date"], '%y-%m-%d')
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
                    object_refs=[vulnerability.id, note.id]
                )
                relationship = Relationship(
                    id = OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                    relationship_type = "related-to",
                    source_ref = vulnerability.id,
                    target_ref = report.id,
                    confidence = self.helper.connect_confidence_level
                )
                bundle = Bundle(
                    objects=[
                        identity,
                        vulnerability,
                        note,
                        report,
                        relationship
                    ],
                    allow_custom=True,
                    entities_types=self.helper.connect_scope,
                    work_id=work_id
                ).serialize()
                self.helper.send_stix2_bundle(bundle)

    def process_data(self):
        try:
            # Get the current timestamp and check
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")
            # If the last_run is more than interval-1 day
            if last_run is None or (
                (timestamp - last_run) > ((int(self.talos_interval) - 1)  / 60 / 60 * 24)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "Talos Connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                self.create_bundle(work_id)
                # Store the current timestamp as a last run
                self.helper.log_info(
                    "Connector successfully run, storing last_run as " + str(timestamp)
                )
                self.helper.set_state({"last_run": timestamp})
                message = (
                    "Last_run stored, next run in: "
                    + str(round(self.get_interval() / 60 / 60 / 24, 2))
                    + " days"
                )
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
            else:
                new_interval = self.get_interval() - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60 / 24, 2))
                    + " days"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            exit(0)
        except Exception as e:
            self.helper.log_error(str(e))


    def run(self):
        self.helper.log_info("Fetching Talos intelligence data...")
        while True:
            self.process_data()
            time.sleep(60)




if "__name__" == "__main__":
    try:
        connector = TemplateConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
