import json
import os

SCHEDULE_FILE = 'schedules.txt'

def load_schedules():
    if os.path.exists(SCHEDULE_FILE):
        with open(SCHEDULE_FILE, 'r') as f:
            return json.load(f)
    return []

def save_schedules(schedules):
    with open(SCHEDULE_FILE, 'w') as f:
        json.dump(schedules, f)

def add_schedule(name, cron, backup_type, sites=None):
    schedules = load_schedules()
    schedules.append({'name': name, 'cron': cron, 'backup_type': backup_type, 'sites': sites or []})
    save_schedules(schedules)

def edit_schedule(idx, name, cron, backup_type, sites=None):
    schedules = load_schedules()
    if 0 <= idx < len(schedules):
        schedules[idx] = {'name': name, 'cron': cron, 'backup_type': backup_type, 'sites': sites or []}
        save_schedules(schedules)

def delete_schedule(idx):
    schedules = load_schedules()
    if 0 <= idx < len(schedules):
        schedules.pop(idx)
        save_schedules(schedules)