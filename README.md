This is a basic python script to access keepass with REST.

# Build the Container
1) Pull from repository
2) docker build -t keepass .

# Start the container
docker run -d -p 8000:8000 --name keepass -v ./data:/data -e KEEPASS_DIR=/data -e API_KEY=SuperSecret keepass

# Environmental variables

* KEEPASS_DIR
This defaults to /data; this directory can be overriden with mount with docker. The DB is initialised ( if does not exists ) here, as well a backup directory, where a DB is saved before each write action.

* DB_PASSWORD
KeePass DB Password; this can be set if a Database is given; tis defaults to "somePassw0rd", which is also used for DB Initialisation.

* API_KEY
This is the API Key which needs to be provided in the X-API-Key header.

The name of the Keepass DB is set to db.kdbx.

The directory "test" shows some basic cURL commands. As the script is using FastAPI, under the /docs a Swagger is available.

