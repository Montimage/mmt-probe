#!/bin/bash
NAMESPACE="test-nginx-app"

kubectl delete -f . -n $NAMESPACE
