In this tutorial, we will use MMT via docker compose.

# Install docker

- document: https://docs.docker.com/engine/install/ubuntu

```bash
# uninstall all conflicting packages:
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove $pkg; done

# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# install the Docker packages
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

# Docker compose

To monitor `enp0s3` NIC of the current computer, then:

- create `docker-compose.yml` file with the following content, then run `sudo docker compose up -d`
- we can access to mmt-operator at http://localhost:3000 (use `admin`/`mmt2nm` as user/pass to login)

```yml
version: '3.9'

services:
  probe:
    container_name: mi_probe
    image: ghcr.io/montimage/mmt-probe:v1.6.0
    command: mmt-probe -i enp0s3 -Xsecurity.enable=true
    restart: unless-stopped
    network_mode: host
    volumes:
      - mi_report_storage:/opt/mmt/probe/result/report/online/:rw
    environment:
      #allow max 100 InitialUEMessage during 1 millisecond
      MMT_SEC_5G_DOS_NGAP_INITIALUEMESSAGE_MS_LIMIT: 100
      #allow max 80 http2 requests having method == 131 or 130, or type == 8
      MMT_SEC_5G_DOS_HTTP2_MS_LIMIT: 80

  mongodb:
    container_name: mi_db
    image: mongo:8
    restart: unless-stopped
    volumes:
      - mi_mongodb_storage:/data/db:rw
    healthcheck:
      test: [ "CMD-SHELL", "mongosh" ]
      interval: 10s
      timeout: 1s
      retries: 5
    networks:
      - mi_metrics

  operator:
    container_name: mi_operator
    image: ghcr.io/montimage/mmt-operator:v1.7.7
    command: /opt/mmt/operator/bin/www -Xdatabase_server.host=mongodb -Xport_number=8080 -Xprobe_analysis_mode=online
    restart: unless-stopped
    ports:
      - 127.0.0.1:3000:8080/tcp #access to GUI from external via port 3000
    # wait for mongodb is available
    depends_on:
      mongodb:
        condition: service_healthy
    # shared volume between mmt-probe and mmt-operator to share CSV reports
    volumes:
      - mi_report_storage:/opt/mmt/probe/result/report/online/:rw
    networks:
      - mi_metrics

volumes:
  mi_mongodb_storage:
  mi_report_storage:

networks:
  mi_metrics:
```

# Inject traffic

We can use [5Greplay](https://5greplay.org/docs.html) to generate some network traffic to test MMT:

```bash
# download test pcap file:
curl -L -o /tmp/test.pcap https://github.com/Montimage/mmt-security/raw/refs/heads/main/test/pcap/test_p9.pcap

# replay the pcap file:
docker run --network=host --rm -it -v/tmp/test.pcap:/x.pcap ghcr.io/montimage/5greplay:v0.0.7 replay -t /x.pcap -Xforward.nb-copies=2000 -Xforward.default=FORWARD -Xforward.output-nic=enp0s3
```

