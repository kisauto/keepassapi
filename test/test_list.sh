#!/bin/bash

source ./env

echo "List entries"

curl -s -X GET "$API_URL/entries" \
     -H "X-API-Key: $API_KEY" \
     -H "Accept: application/json" | jq '.'

