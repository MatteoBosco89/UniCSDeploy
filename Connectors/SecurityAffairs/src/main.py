import os
import yaml
import traceback
import time
from pycti import OpenCTIConnectorHelper, get_config_variable, OpenCTIStix2Utils
from stix2 import Bundle, Report, AttackPattern, Identity, ExternalReference
from datetime import datetime
from scrap.Scraper import Scraper
from email.utils import parsedate_tz, mktime_tz


class SecurityAffairs:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.securityaffairs_interval = get_config_variable(
            "SECURITYAFFAIRS_INTERVAL", ["securityaffairs", "interval"], config, True
        )

    def get_interval(self) -> int:
        return int(self.securityaffairs_interval) * 60 * 60 * 24

    def create_bundle(self, work_id):
        try:
            scraper = Scraper()
            bundleObjects = []
            data = scraper.getAllArticles()
            security_site = ExternalReference(
                #https://securityaffairs.co/
                url = "https://securityaffairs.co/",
                description = "Cyber Security Blog of Engineer Pierluigi Paganini",
                source_name = "Securityaffairs.co"
            )
            identity = Identity(
                id=OpenCTIStix2Utils.generate_random_stix_id("identity"),
                name="SecurityAffairs",
                external_references=[security_site]
            )
            security_linkedin = ExternalReference(
                #http://www.linkedin.com/pub/pierluigi-paganini/b/742/559
                url = "http://www.linkedin.com/pub/pierluigi-paganini/b/742/559",
                description = "Linkedin profile of Engineer Pierluigi Paganini",
                source_name = "Linkedin.com"
            )
            security_twitter = ExternalReference(
                #https://twitter.com/securityaffairs
                url = "https://twitter.com/securityaffairs",
                description = "Twitter profile of SecurityAffairs",
                source_name = "Twitter.com"
            )
            bundleObjects.append(identity)
            if(data is not None):
                for d in data:
                    link = ExternalReference(
                        url = d["link"],
                        description = "Link to the SecurityAffairs Articles",
                        source_name = "Securityaffairs.co"
                    )
                    attack_pattern = AttackPattern(
                        id=OpenCTIStix2Utils.generate_random_stix_id("attack-pattern"),
                        name = d["title"],
                        description = d["description"],
                        labels=["SecurityAffairs"]
                    )
                    report = Report(
                        id = OpenCTIStix2Utils.generate_random_stix_id("report"),
                        report_types = ["note"],
                        description = d["description"],
                        name = d["title"],
                        labels = d["labels"],
                        created_by_ref = identity.id,
                        published = d["pubdate"],
                        object_refs = [identity.id, attack_pattern.id],
                        external_references = [
                            security_site,
                            security_linkedin,
                            security_twitter,
                            link
                        ]
                    )
                    bundleObjects.append(attack_pattern)
                    bundleObjects.append(report)
                bundle = Bundle(objects=bundleObjects, allow_custom=True).serialize()
                self.helper.send_stix2_bundle(bundle, work_id=work_id)
            else:
                self.helper.log_info("Got nothing from page :(")
        except Exception as e:
            self.helper.log_info(e)
            self.helper.log_info(traceback.format_exc())

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
                (timestamp - last_run) > ((int(self.securityaffairs_interval) - 1) * 60 * 60 * 24)
            ):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "SecurityAffairs Connector run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
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
        self.helper.log_info("Fetching SecurityAffairs feeds...")
        while True:
            self.process_data()
            time.sleep(60)




if __name__ == "__main__":
    try:
        connector = SecurityAffairs()
        connector.run()
    except Exception as e:
        print(e)
        print(traceback.format_exc())
        time.sleep(10)
        exit(0)
