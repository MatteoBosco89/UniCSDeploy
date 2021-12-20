# OpenCTI TalosIntelligence Connector
#### Team UniCS

* The OpenCTI TalosIntelligence Connector can be used to import knowledge from https://talosintelligence.com/ feeds. 

  **Note**: Nothing is required but the working platform to use the connector

## Installation

### Requirements

- OpenCTI Platform >= 5.0.3

- The best way to install the connector is by the Portainer dashboard, but furthermore, is installable with Docker Compose and runnable with Python. 

  It must have access to the platform and RabbitMQ instance, through the OpenCTI Connector Token, obtainable through a New User creation. 

### Installation Process

- Standalone Python Process: provide the correct configuration in the `config.yml` file, install all the requirements in the `requirements.txt` file with `pip3 install -r requirements.txt -U` and start the process in detached mode using the `&` keyword `python3 main.py &`

- Docker Compose Process: provide the correct configuration in the `docker-compose.yml` file and start the container using the command `docker-compose up` 

- Portainer Process: provide the correct configuration inside the stack in the Portainer Dashboard and press the `Update the Stack` button

  

### Configuration

| Docker envvar                | Parameter                    | Default                                                      | Description                                                  |
| ---------------------------- | ---------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `OPENCTI_URL`                | `opencti_url`                | `http://opencti:8080`                                        | The URL of the OpenCTI platform.                             |
| `OPENCTI_TOKEN`              | `opencti_token`              | `changeMe`                                                   | The user token provided in the OpenCTI platform.             |
| `CONNECTOR_ID`               | `connector_id`               | `changeMe`                                                   | A valid arbitrary `UUIDv4` that must be unique for this connector. |
| `CONNECTOR_TYPE`             | `connector_type`             | `EXTERNAL_IMPORT`                                            | Must be `EXTERNAL_IMPORT` (this is the connector type).      |
| `CONNECTOR_NAME`             | `connector_name`             | `TalosIntelligence`                                          | Option `TalosIntelligence`                                   |
| `CONNECTOR_SCOPE`            | `connector_scope`            | `Bundle, Malware, Report, Note, Relationship, Identity, ExternalReference` | Supported scope: Template Scope (MIME Type or Stix Object)   |
| `CONNECTOR_CONFIDENCE_LEVEL` | `connector_confidence_level` | `100`                                                        | The default confidence level for created sightings (a number between 0 and 100). |
| `CONNECTOR_LOG_LEVEL`        | `connector_log_level`        | `info`                                                       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `TALOS_INTERVAL`             | `talos_interval`             | `2`                                                          | Must be strictly greater than 1, indicates the frequency of update in days (default value is 2 days). |



