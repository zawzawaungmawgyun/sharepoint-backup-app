import os
import requests
from msal import ConfidentialClientApplication
import json
import time

progress = {
    "current": 0,
    "total": 0,
    "percent": 0,
    "status": "Idle"
}

backup_results = {
    "full": [],
    "incremental": []
}

HISTORY_FILE = 'backup_history.json'

def get_token():
    client_id = os.getenv('CLIENT_ID')
    client_secret = os.getenv('CLIENT_SECRET')
    tenant_id = os.getenv('TENANT_ID')
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    scope = ["https://graph.microsoft.com/.default"]

    app = ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )
    result = app.acquire_token_silent(scope, account=None)
    if not result:
        result = app.acquire_token_for_client(scopes=scope)
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception("Could not obtain access token")

def get_site_and_drive_ids(site_url, headers):
    site_hostname = site_url.split('/')[2]
    site_path = '/'.join(site_url.split('/')[4:])
    site_api = f"https://graph.microsoft.com/v1.0/sites/{site_hostname}:/sites/{site_path}"
    site_resp = requests.get(site_api, headers=headers)
    if site_resp.status_code != 200:
        print(f"Failed to get site info for {site_url}")
        print(site_resp.text)
        return None, None
    site_id = site_resp.json()['id']
    drives_api = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives"
    drives_resp = requests.get(drives_api, headers=headers)
    if drives_resp.status_code != 200:
        print(f"Failed to get drives for {site_url}")
        print(drives_resp.text)
        return site_id, None
    drive_ids = [d['id'] for d in drives_resp.json().get('value', [])]
    return site_id, drive_ids

def list_files_recursive(drive_id, folder_id, headers, path_prefix=""):
    files = []
    url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{folder_id}/children"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        print(f"Failed to list folder {folder_id}")
        return files
    for item in resp.json().get('value', []):
        item_path = os.path.join(path_prefix, item['name'])
        if 'folder' in item:
            files += list_files_recursive(drive_id, item['id'], headers, item_path)
        elif 'file' in item:
            files.append({
                "drive_id": drive_id,
                "item_id": item['id'],
                "name": item['name'],
                "path": item_path,
                "download_url": item['@microsoft.graph.downloadUrl']
            })
    return files

def list_sharepoint_files(site_url):
    token = get_token()
    headers = {"Authorization": f"Bearer {token}"}
    site_id, drive_ids = get_site_and_drive_ids(site_url, headers)
    all_files = []
    if not drive_ids:
        return all_files
    for drive_id in drive_ids:
        # Get drive (library) name
        drive_api = f"https://graph.microsoft.com/v1.0/drives/{drive_id}"
        drive_resp = requests.get(drive_api, headers=headers)
        if drive_resp.status_code != 200:
            continue
        drive_name = drive_resp.json().get('name', 'UnknownLibrary')
        # Get root folder id
        root_api = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root"
        root_resp = requests.get(root_api, headers=headers)
        if root_resp.status_code != 200:
            continue
        root_id = root_resp.json()['id']
        # Pass drive_name to recursive listing
        all_files += list_files_recursive(drive_id, root_id, headers, path_prefix=drive_name)
    return all_files

def download_sharepoint_file(site_url, file_info, backup_path, incremental=False):
    site_folder = os.path.join(
        backup_path,
        site_url.replace('/', '_')
    )
    file_path = os.path.join(site_folder, file_info['path'])
    if file_info.get('type', 'file') == 'folder':
        os.makedirs(file_path, exist_ok=True)
        print(f"Created folder {file_info['path']} from {site_url}")
    elif file_info.get('type', 'file') == 'file':
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with requests.get(file_info['download_url'], stream=True) as r:
            with open(file_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print(f"Downloaded {file_info['path']} from {site_url}")

def run_backup(site_urls, incremental=False):
    global progress, backup_results
    backup_type = "incremental" if incremental else "full"
    backup_results[backup_type] = []
    backup_path = os.getenv('BACKUP_PATH', '/mnt/backup')
    all_files = []
    for url in site_urls:
        try:
            files = list_sharepoint_files(url)
            all_files.extend([(url, f) for f in files])
            backup_results[backup_type].append({"site": url, "status": "success"})
            log_backup_history(url, backup_type, "success")
        except Exception as e:
            backup_results[backup_type].append({"site": url, "status": "fail", "error": str(e)})
            log_backup_history(url, backup_type, "fail", str(e))
    progress["total"] = len(all_files)
    progress["current"] = 0
    progress["status"] = "Running"
    if not all_files:
        progress["status"] = "No files found"
        progress["percent"] = 100
        return
    for idx, (url, file_info) in enumerate(all_files, 1):
        download_sharepoint_file(url, file_info, backup_path, incremental)
        progress["current"] = idx
        progress["percent"] = int((idx / progress["total"]) * 100)
    progress["status"] = "Done"

def get_disk_space(path):
    st = os.statvfs(path)
    free = st.f_bavail * st.f_frsize // (1024**3)
    total = st.f_blocks * st.f_frsize // (1024**3)
    return {'free': free, 'total': total}

def list_all_folders(drive_id, headers):
    url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/list/items?expand=fields"
    folders = []
    while url:
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            break
        for item in resp.json().get('value', []):
            if item.get('folder'):
                folders.append(item)
        url = resp.json().get('@odata.nextLink')
    return folders

def log_backup_history(site, backup_type, status, details=""):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "site": site,
        "backup_type": backup_type,
        "status": status,
        "details": details
    }
    history = load_backup_history()
    history.insert(0, entry)  # newest first
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f)

def load_backup_history():
    try:
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []