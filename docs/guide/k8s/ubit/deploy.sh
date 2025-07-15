#!/bin/bash

#0. create mmt namespace
kubectl create namespace montimage
#1. deploy Kafka and Zookeeper
kubectl apply -f ./kafka.yml -n montimage
#2. deploy MongoDB
kubectl apply -f ./mongo.yml -n montimage
# wait for the MongoDB Pod being available (~20 seconds)
#3. deploy MMT-Operator
kubectl apply -f ./mmt-operator.yml -n montimage
#4. deploy nginx server whose traffic will be monitored by MMT-Probe
kubectl apply -f ./mmt-probe.yml -n montimage