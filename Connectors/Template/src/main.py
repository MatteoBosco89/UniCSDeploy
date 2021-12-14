import yaml
import os
import requests
import pycountry

from stix2 import Location, Bundle, Sighting, Malware
from pycti import OpenCTIConnectorHelper, OpenCTIStix2Utils, get_config_variable


class MalwareBazarConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_key = get_config_variable(
            "MALWAREBAZAR_API_KEY", ["malwarebazar", "api_key"], config
        )

    def _generate_stix_bundle(self, data, observable_id):
        # Generate stix bundle

        country_location = None
        malware = None
        sighting = None


        sha256_hash = data['sha256_hash']
        sha3_384_hash = data['sha3_384_hash']
        sha1_hash = data['sha1_hash']
        md5_hash = data['md5_hash']
        first_seen = data['first_seen']
        last_seen = data['last_seen']
        file_name = data['file_name']
        file_size = data['file_size']
        file_type_mime = data['file_type_mime']
        file_type = data['file_type']
        reporter = data['reporter']
        origin_country = data['origin_country']
        anonymous = data['anonymous']
        signature = data['signature'] 
        imphash = data['imphash']
        tlsh = data['tlsh']
        telfhash = data['telfhash']
        ssdeep = data['ssdeep']
        dhash_icon = data['dhash_icon']
        
        

        sighting = Sighting()

        country = pycountry.countries.get(alpha_2=data["origin_country"])
            if country is None:
                raise ValueError(
                    "No Country found"
                )
            else:
                country_location = Location(
                    id=OpenCTIStix2Utils.generate_random_stix_id("location"),
                    name=country.name,
                    country=country.official_name
                    if hasattr(country, "official_name")
                    else country.name,
                    custom_properties={
                        "x_opencti_location_type": "Country",
                        "x_opencti_aliases": [
                            country.official_name
                            if hasattr(country, "official_name")
                            else country.name
                        ],
                    },
                )

        malware = Malware(
            id=
        )

        sighting = Sighting(

        )

        observable_to_city = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="located-at",
            source_ref=observable_id,
            target_ref=city_location.id,
            confidence=self.helper.connect_confidence_level,
        )

        city_to_country = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="located-at",
            source_ref=city_location.id,
            target_ref=country_location.id,
        )
        observable_to_city = Relationship(
            id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
            relationship_type="located-at",
            source_ref=observable_id,
            target_ref=city_location.id,
            confidence=self.helper.connect_confidence_level,
        )
        return Bundle(
            objects=[
                country_location,
                city_location,
                city_to_country,
                observable_to_city,
            ],
            allow_custom=True,
        ).serialize()

    def _process_message(self, data: Dict) -> str:
		entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )		
        observable_id = observable["standard_id"]
        observable_value = observable["value"]	
        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "API-KEY": "%s" % self.api_key,
        }
        params = {"selector": "time", "query": "get_recent"}	
        r = requests.post(url, headers=headers, data=params)
        r.raise_for_status()
        data = r.json()
        if(data["query_status"] == "ok"):
            data = data["data"]
            for k in data
            bundle = self._generate_stix_bundle(
                data, observable_id
            )
            bundles_sent = self.helper.send_stix2_bundle(bundle)
            print("Sent " + str(len(bundles_sent)) + " stix bundle(s) for worker import")
        return "Messages Processed"
        

    # Start the main loop
    def start(self) -> None:
        self.helper.listen(self._process_message)

    
    ####
    # TODO add your code according to your connector type
    # For details: see
    # https://www.notion.so/luatix/Connector-Development-06b2690697404b5ebc6e3556a1385940
    ####


if __name__ == "__main__":
    try:
        connector = MalwareBazarConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
