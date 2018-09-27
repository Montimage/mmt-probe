#!/bin/bash

# This script listes all processes used by MMT

ps af --no-headers -o 'pid,cmd' | grep --color=auto '\.js\|\.sh\|\./probe\|ba\ \|bw\ \|node\|mongod'