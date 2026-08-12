#!/bin/bash

source ./env

curl -s -X POST "$API_URL/entries" \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "title": "blabla",
       "username": "root",
       "password": "super",
       "hostname": "hsotname",
       "custom_json": {
         "ssh_port": 22,
         "backup_enabled": true,
         "monitoring_id": "asdf"
       }
     }' | jq '.'


