This tutorial shows how to quickly deploy MMT in a Kubernetes cluster.

# Deployment

The following steps will deploy MMT together with nginx that is an example of the application to be monitored by MMT. To do so, MMT-Probe and nginx are deployed into the same pod so that MMT-Probe can capture all in/outgoin traffic of the pod.

```bash
#0. create mmt namespace
kubectl create namespace mmt
#1. deploy Kafka and Zookeeper
kuberctl apply -f ./kafka.yml -n mmt
#2. deploy MongoDB
kuberctl apply -f ./mongo.yml -n mmt
# wait for the MongoDB Pod being available (~20 seconds)
#3. deploy MMT-Operator
kuberctl apply -f ./mmt-operator.yml -n mmt
#4. deploy nginx server whose traffic will be monitored by MMT-Probe
```

# Test

## Kafka:
Run the following command inside the console of the Kafka pod:

+ list all topics: `/opt/bitnami/kafka/bin/kafka-topics.sh --bootstrap-server=localhost:9092 --describe --topic mmt-reports`

+ subscribe to a topic: `/opt/bitnami/kafka/bin/kafka-console-consumer.sh  --bootstrap-server localhost:9092  --topic mmt-reports  --from-beginning`

+ list all consumers: `/opt/bitnami/kafka/bin/kafka-consumer-groups.sh --list --bootstrap-server localhost:9092`
