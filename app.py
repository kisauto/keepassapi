import os
import shutil
import json
import threading
from typing import Optional, Any, Dict

from fastapi import FastAPI, HTTPException, Security, Depends, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from pykeepass import PyKeePass, create_database

# 1. Konfiguration aus Umgebungsvariablen laden
DB_FILE = os.getenv("KEEPASS_DB", "db.kdbx")
DB_PASSWORD = os.getenv("KEEPASS_PASSWORD", "somePassw0rd")
BACKUP_DIR = os.getenv("KEEPASS_BACKUP_DIR", "./backups")
API_KEY = os.getenv("KEEPASS_API_KEY", "SuperSecure")

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

_write_lock = threading.Lock()
kp: Optional[PyKeePass] = None

class PWEntry(BaseModel):
    title: str
    username: str
    password: str
    hostname: str
    custom_json: Dict[str, Any]

class PWUpdateEntry(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    hostname: Optional[str] = None
    custom_json: Optional[Dict[str, Any]] = None

# 2. Hilfsfunktionen (MÜSSEN oben stehen)
def get_api_key(header_key: str = Security(api_key_header)):
    if not header_key or header_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials. Invalid or missing API Key."
        )
    return header_key

def parse_custom_json(entry) -> Dict[str, Any]:
    raw_json = entry.get_custom_property("custom_json")
    if raw_json:
        try:
            return json.loads(raw_json)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON data stored in database"}
    return {}

def save_and_reopen_database():
    """
    Erstellt ein Backup, speichert die Daten ab und öffnet die Datei neu,
    damit alle internen XML-Indizes im RAM garantiert aktuell sind.
    """
    global kp
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_file = os.path.join(BACKUP_DIR, f"{os.path.basename(DB_FILE)}.bak")
    tmp_file = f"{DB_FILE}.tmp"
    
    try:
        if os.path.exists(DB_FILE):
            shutil.copy2(DB_FILE, backup_file)
            
        kp.save(filename=tmp_file)
        os.replace(tmp_file, DB_FILE)
        
        # Zwingt die App, die Daten-Indizes frisch im RAM zu halten
        kp = PyKeePass(DB_FILE, DB_PASSWORD)
    except Exception as e:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
        raise e

# 3. Datenbank beim Booten laden
try:
    if not os.path.exists(DB_FILE):
        kp = create_database(DB_FILE, password=DB_PASSWORD)
        kp.save()
    else:
        kp = PyKeePass(DB_FILE, DB_PASSWORD)
except Exception as e:
    print(f"Database initialization failed: {e}")
    exit(1)

app = FastAPI()

# 4. API Endpunkte
@app.get("/entries/{title}", dependencies=[Depends(get_api_key)])
@app.get("/entries", dependencies=[Depends(get_api_key)])
def get_entries(title: Optional[str] = None):
    if title is None:
        _entries = []
        for _e in kp.entries:
            _entries.append({
                "title": _e.title,
                "username": _e.username,
                "hostname": _e.get_custom_property("hostname") or "",
                "custom_json": parse_custom_json(_e)
            })
        return {"length": len(_entries), "result": _entries}
    else:
        _e = kp.find_entries(title=title, first=True)
        if _e is not None:
            return {
                "title": _e.title,
                "username": _e.username,
                "password": _e.password,
                "hostname": _e.get_custom_property("hostname") or "",
                "custom_json": parse_custom_json(_e)
            }
        raise HTTPException(status_code=404, detail="No entry found")

@app.post("/entries", status_code=201, dependencies=[Depends(get_api_key)])
def add_entry(entry: PWEntry):
    with _write_lock:
        if kp.find_entries(title=entry.title, first=True) is not None:
            raise HTTPException(status_code=409, detail=f"An entry '{entry.title}' already exists.")
            
        try:
            _e = kp.add_entry(kp.root_group, entry.title, entry.username, entry.password)
            _e.set_custom_property("hostname", entry.hostname)
            _e.set_custom_property("custom_json", json.dumps(entry.custom_json))
            
            save_and_reopen_database()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Item can not be created: {e}")
        return entry

@app.patch("/entries/{title}", dependencies=[Depends(get_api_key)])
def update_entry(title: str, entry_update: PWUpdateEntry):
    with _write_lock:
        _e = kp.find_entries(title=title, first=True)
        if _e is None:
            raise HTTPException(status_code=404, detail="Entry not found")
        
        if entry_update.username is not None:
            _e.username = entry_update.username
        if entry_update.password is not None:
            _e.password = entry_update.password
        if entry_update.hostname is not None:
            _e.set_custom_property("hostname", entry_update.hostname)
        if entry_update.custom_json is not None:
            _e.set_custom_property("custom_json", json.dumps(entry_update.custom_json))
            
        try:
            save_and_reopen_database()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Could not save changes: {e}")
            
        return {
            "title": _e.title,
            "username": _e.username,
            "password": _e.password,
            "hostname": _e.get_custom_property("hostname") or "",
            "custom_json": parse_custom_json(_e)
        }
