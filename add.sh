#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: sh run.sh <username> <password>"
    exit 1
fi

USERNAME=$1
PASSWORD=$2

go run main.go adduser $USERNAME $PASSWORD

kill $(lsof -t -i:1080)

nohup go run main.go &