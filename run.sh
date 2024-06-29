#!/bin/bash

kill $(lsof -t -i:1080)

nohup go run main.go &