import os
import yaml
import traceback
import time
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIStix2Utils
from stix2 import Bundle, Malware, Report, Note, Relationship, Identity, ExternalReference
from datetime import datetime
from email.utils import parsedate_tz, mktime_tz
import cloudscraper
import xmltodict


class BleepingConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.bleeping_interval = get_config_variable(
            "BLEEPING_INTERVAL", ["bleeping", "interval"], config, True
        )

    def get_interval(self) -> int:
        return int(self.bleeping_interval) * 60 * 60 * 24

    def create_bundle(self, work_id):
        scraper = cloudscraper.create_scraper()
        url = "https://www.bleepingcomputer.com/startups/feed/"
        data = scraper.get(url).text
        l = xmltodict.parse(data)
        l1 = l.get('rss').get('channel').get('item')
        ext_re_blee = ExternalReference(
            source_name="BleepingComputer",
            description="BleepingComputer.com is a premier destination for computer users of all skill levels to learn how to use and receive support for their computer.",
            url="https://www.bleepingcomputer.com/"
        )
        identity = Identity(
            id=OpenCTIStix2Utils.generate_random_stix_id("identity"),
            name="BleepingComputer",
            external_references=[ext_re_blee]
        )
        for l2 in l1:
            timestamp = mktime_tz(parsedate_tz(l2.get('pubDate')))
            pubdt = datetime.fromtimestamp(timestamp)
            ext_re = ExternalReference(
                source_name="BleepingComputer",
                description="BleepingComputer.com is a premier destination for computer users of all skill levels to learn how to use and receive support for their computer.",
                url=l2.get('link')
            )            
            malware = Malware(
                id=OpenCTIStix2Utils.generate_random_stix_id("malware"),
                is_family=False,
                name=l2.get('title'),
                description=l2.get('link'),
                labels=["malware"],
                external_references=[ext_re]
            )
            report = Report(
                id=OpenCTIStix2Utils.generate_random_stix_id("report"),
                report_types=["malware"],
                name=l2.get('title'),
                published=pubdt,
                labels=["malware"],
                object_refs=[malware.id],
                created_by_ref=identity.id,
                external_references=[ext_re]
            )
            note = Note(
                id=OpenCTIStix2Utils.generate_random_stix_id("note"),
                content=l2.get('title'),
                object_refs=[malware.id, report.id],
                labels=["malware"],
                external_references=[ext_re]
            )
            relrr = Relationship(
                id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                relationship_type="related-to",
                source_ref=malware.id,
                target_ref=report.id,
                confidence=self.helper.connect_confidence_level,
                external_references=[ext_re]
            )
            bundle = Bundle(
                objects=[
                    identity,
                    malware,
                    report,
                    note,
                    relrr
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
                (timestamp - last_run) > ((int(self.bleeping_interval) - 1) * 60 * 60 * 24)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "Bleeping Connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
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
        self.helper.log_info("Fetching bleepingcomputer feeds...")
        while True:
            self.process_data()
            time.sleep(60)
        



if __name__ == "__main__":
    try:
        connector = BleepingConnector()
        connector.run()
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        time.sleep(10)
        exit(0)
