#!/bin/bash
NAMESPACE="test-nginx-app"

kubectl create namespace $NAMESPACE
kubectl label namespace $NAMESPACE istio-injection=enabled --overwrite
kubectl apply -f . -n $NAMESPACE
