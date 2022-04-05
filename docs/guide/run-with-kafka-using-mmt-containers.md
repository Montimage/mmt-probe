In the following tutorial, we will se how to use MMT via docker containers and the communication using Kafka bus.

# Start MMT-Probe

The following command will start MMT-Probe to analyse network traffic:
- `eth0`: NIC to capture traffic
- `10.0.37.5`: is IP address of kafka server
- `30031`: is port of kafka server

```bash 
docker run --name mmt-probe ghcr.io/montimage/mmt-probe:latest -i eth0 -Xkafka-output.enable=true -Xkafka-output.hostname=10.0.37.5 -Xkafka-output.port=30031
```

By default, the reports will be written on `mi-reports` topic. This can be change via `kafka-output.topic`, e.g., add this parameter `-Xkafka-output.topic=network-reports` to set topic's name `network-reports`

You can obtain the list of command parameter by running `docker run --rm ghcr.io/montimage/mmt-probe:latest -x`.

For any further configuration, please see [docs](https://github.com/Montimage/mmt-probe/tree/master/docs) or [MMT-Manual](https://github.com/Montimage/mmt-manual)


# Start MMT-Operator

The following command will run [MMT-Operator](https://github.com/Montimage/mmt-operator) to display graphically the reports generated by MMT-Probe.
To do so, you need a MongoDB server. In this command, the server is listenning at `10.0.0.2:27017` (we do not need to set the port as `27017` is the default one, otherwise use `-Xdatabase_server.port` to set a new port number).

```bash
docker run -p8080:8080 --name mmt-operator ghcr.io/montimage/mmt-operator:latest -Xdatabase_server.host=10.0.0.2 -Xinput_mode=kafka -Xkafka_input.host=10.0.37.5 -Xkafka_input.port=30031
```

For any further configuration, please see [docs](https://github.com/Montimage/mmt-operator/tree/main/doc) or [MMT-Manual](https://github.com/Montimage/mmt-manual)