#!/bin/bash

source ./env

TITLE="blabla"

curl -s -X GET "$API_URL/entries/$TITLE" \
     -H "X-API-Key: $API_KEY" \
     -H "Accept: application/json" | jq '.'


