# Malicious-Traffic-Research

Research on different attack vectors, including DDoS attack types, payloads and a honeypot sensor to detect malicious actors.

The result of this research project is available in the repository's subfolders and will include the following:

- `README.md` that contains Protocol and payload Information. Attack vectors and flaws and how they can be abused by malicious actors.
- Honeypot service for the protocol to collect more information about malicious actors.
- Based on the protocol or analysed vulnerability, the directory may contain PCAP data which contains sample attack traffic.


## Honeypot Services
All of the implemented services are built and docker images available [here](https://github.com/im4kv/Malicious-Traffic-Research/pkgs/container/malicious-traffic-research). To run the Honeypot services, you should use docker compose with the provided `docker-compose.yml` file:
1)  Install Docker Compose in the machine that you want to run Honeypot services
2)  A Web-Based service is also defined in the `docker-compose.yml` to access the containers logs which contains incoming connection requests and malicious actions. The service (defined as `dozzle`) is disabled by default. you can enable it by removing the profile section under the service. since the service doesn't have any authentication mechanism make sure you restrict access to specific endpoint via your firewall.
    <pre>
    dozzle:
        container_name: dozzle
        restart: always
        # profiles section commented to enable the service
        # profiles:
        #  - donotstart
    </pre>
3) Run the services with docker-compose:
    <pre>
    docker-compose up
    </pre>
