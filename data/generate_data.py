"""
Synthetic Industrial Access Log Generator
150 users, 60 days, 5 injected attack types with ground-truth labels.
"""
import pandas as pd
import numpy as np
from faker import Faker
from datetime import datetime, timedelta
import random
import uuid

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
fake = Faker()
Faker.seed(SEED)

NUM_USERS = 150
NUM_DAYS = 60
START_DATE = datetime(2025, 1, 1)

RESOURCES = [
    "Engineering_Workstation", "SCADA_HMI", "PLC_Controller_01", "PLC_Controller_02",
    "PLC_Controller_03", "PLC_Controller_04", "Process_Historian_DB", "HVAC_Controller",
    "Building_Access_System", "File_Server_01", "File_Server_02", "Email_Server",
    "ERP_System", "VPN_Gateway", "Domain_Controller", "Backup_Server",
    "CCTV_System", "Badge_Reader_Gate_A", "Badge_Reader_Gate_B", "R&D_Repository"
]

ROLES = ["engineer", "operator", "admin", "analyst", "contractor", "manager"]

ROLE_RESOURCE_MAP = {
    "engineer": ["Engineering_Workstation", "SCADA_HMI", "PLC_Controller_01", "PLC_Controller_02",
                 "PLC_Controller_03", "PLC_Controller_04", "Process_Historian_DB", "File_Server_01"],
    "operator": ["SCADA_HMI", "PLC_Controller_01", "PLC_Controller_02", "HVAC_Controller",
                 "Badge_Reader_Gate_A"],
    "admin": ["Domain_Controller", "Backup_Server", "VPN_Gateway", "File_Server_01",
              "File_Server_02", "ERP_System"],
    "analyst": ["Process_Historian_DB", "ERP_System", "File_Server_02", "Email_Server"],
    "contractor": ["Badge_Reader_Gate_B", "HVAC_Controller", "File_Server_02"],
    "manager": ["ERP_System", "Email_Server", "File_Server_01", "File_Server_02"]
}

# City -> (lat, lon) pool for geo-velocity feature later
CITIES = [
    ("New York", 40.7128, -74.0060), ("Chicago", 41.8781, -87.6298),
    ("Dallas", 32.7767, -96.7970), ("Phoenix", 33.4484, -112.0740),
    ("Atlanta", 33.7490, -84.3880), ("Denver", 39.7392, -104.9903),
    ("Seattle", 47.6062, -122.3321), ("Boston", 42.3601, -71.0589)
]

TRAVELER_CITY_POOL = [
    ("London", 51.5074, -0.1278), ("Singapore", 1.3521, 103.8198),
    ("Tokyo", 35.6762, 139.6503), ("Frankfurt", 50.1109, 8.6821)
]


def build_users():
    users = []
    for i in range(NUM_USERS):
        role = random.choice(ROLES)
        home_city = random.choice(CITIES)
        device_id = f"DEV-{uuid.uuid4().hex[:8]}"
        is_traveler = random.random() < 0.05  # ~7-8 legit irregular travelers
        users.append({
            "user_id": f"U{i+1:04d}",
            "username": fake.user_name(),
            "role": role,
            "home_city": home_city[0],
            "home_lat": home_city[1],
            "home_lon": home_city[2],
            "known_devices": [device_id],
            "normal_resources": ROLE_RESOURCE_MAP[role],
            "is_traveler": is_traveler,
            "typical_hour": random.choice([8, 9, 10, 13, 14])
        })
    return users


def haversine_km(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, sqrt, atan2
    R = 6371
    dlat, dlon = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1))*cos(radians(lat2))*sin(dlon/2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))


def normal_event(user, ts):
    resource = random.choice(user["normal_resources"])
    lat, lon = user["home_lat"], user["home_lon"]
    return {
        "log_id": str(uuid.uuid4()),
        "timestamp": ts,
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "device_id": user["known_devices"][0],
        "device_known": True,
        "resource": resource,
        "action": random.choice(["login", "read", "write", "access"]),
        "status": "success",
        "latitude": lat,
        "longitude": lon,
        "city": user["home_city"],
        "attack_type": "none",
        "is_attack": 0
    }


def inject_brute_force(user, ts, log_rows):
    n_attempts = random.randint(6, 15)
    for i in range(n_attempts):
        attempt_ts = ts + timedelta(seconds=i * random.randint(2, 8))
        log_rows.append({
            "log_id": str(uuid.uuid4()), "timestamp": attempt_ts,
            "user_id": user["user_id"], "username": user["username"], "role": user["role"],
            "device_id": user["known_devices"][0], "device_known": True,
            "resource": "VPN_Gateway", "action": "login",
            "status": "success" if i == n_attempts - 1 else "failed",
            "latitude": user["home_lat"], "longitude": user["home_lon"], "city": user["home_city"],
            "attack_type": "brute_force", "is_attack": 1
        })


def inject_credential_misuse(user, ts, log_rows):
    off_role_resource = random.choice(
        [r for r in RESOURCES if r not in user["normal_resources"]]
    )
    log_rows.append({
        "log_id": str(uuid.uuid4()), "timestamp": ts,
        "user_id": user["user_id"], "username": user["username"], "role": user["role"],
        "device_id": user["known_devices"][0], "device_known": True,
        "resource": off_role_resource, "action": random.choice(["read", "write", "access"]),
        "status": "success",
        "latitude": user["home_lat"], "longitude": user["home_lon"], "city": user["home_city"],
        "attack_type": "credential_misuse", "is_attack": 1
    })


def inject_lateral_movement(user, ts, log_rows):
    chain = ["Engineering_Workstation", "SCADA_HMI", "PLC_Controller_04", "Process_Historian_DB"]
    for i, res in enumerate(chain):
        log_rows.append({
            "log_id": str(uuid.uuid4()), "timestamp": ts + timedelta(minutes=i * 2),
            "user_id": user["user_id"], "username": user["username"], "role": user["role"],
            "device_id": user["known_devices"][0], "device_known": True,
            "resource": res, "action": "access", "status": "success",
            "latitude": user["home_lat"], "longitude": user["home_lon"], "city": user["home_city"],
            "attack_type": "lateral_movement", "is_attack": 1
        })


def inject_impossible_travel(user, ts, log_rows):
    far_city = random.choice(TRAVELER_CITY_POOL)
    dist = haversine_km(user["home_lat"], user["home_lon"], far_city[1], far_city[2])
    log_rows.append({
        "log_id": str(uuid.uuid4()), "timestamp": ts,
        "user_id": user["user_id"], "username": user["username"], "role": user["role"],
        "device_id": user["known_devices"][0], "device_known": True,
        "resource": random.choice(user["normal_resources"]), "action": "login", "status": "success",
        "latitude": far_city[1], "longitude": far_city[2], "city": far_city[0],
        "attack_type": "impossible_travel", "is_attack": 1
    })
    # a normal-city login within minutes makes the "impossible" part detectable later
    log_rows.append({
        "log_id": str(uuid.uuid4()), "timestamp": ts + timedelta(minutes=12),
        "user_id": user["user_id"], "username": user["username"], "role": user["role"],
        "device_id": user["known_devices"][0], "device_known": True,
        "resource": random.choice(user["normal_resources"]), "action": "login", "status": "success",
        "latitude": user["home_lat"], "longitude": user["home_lon"], "city": user["home_city"],
        "attack_type": "impossible_travel", "is_attack": 1
    })


def inject_device_spoofing(user, ts, log_rows):
    fake_device = f"DEV-{uuid.uuid4().hex[:8]}"
    log_rows.append({
        "log_id": str(uuid.uuid4()), "timestamp": ts,
        "user_id": user["user_id"], "username": user["username"], "role": user["role"],
        "device_id": fake_device, "device_known": False,
        "resource": random.choice(user["normal_resources"]), "action": "login", "status": "success",
        "latitude": user["home_lat"], "longitude": user["home_lon"], "city": user["home_city"],
        "attack_type": "device_spoofing", "is_attack": 1
    })


ATTACK_INJECTORS = {
    "brute_force": inject_brute_force,
    "credential_misuse": inject_credential_misuse,
    "lateral_movement": inject_lateral_movement,
    "impossible_travel": inject_impossible_travel,
    "device_spoofing": inject_device_spoofing
}

ATTACK_RATE = 0.06  # ~6% of user-days get an injected attack


def generate():
    users = build_users()
    log_rows = []

    for day in range(NUM_DAYS):
        day_date = START_DATE + timedelta(days=day)
        for user in users:
            # legit traveler: occasionally logs in from a different real city (NOT labeled attack)
            if user["is_traveler"] and random.random() < 0.1:
                city = random.choice(CITIES)
                n_events = random.randint(2, 5)
                for _ in range(n_events):
                    hour = user["typical_hour"] + random.randint(-1, 2)
                    ts = day_date + timedelta(hours=hour, minutes=random.randint(0, 59))
                    ev = normal_event(user, ts)
                    ev["latitude"], ev["longitude"], ev["city"] = city[1], city[2], city[0]
                    log_rows.append(ev)
                continue

            n_events = random.randint(3, 8)
            for _ in range(n_events):
                hour = user["typical_hour"] + random.randint(-2, 3)
                hour = max(0, min(23, hour))
                ts = day_date + timedelta(hours=hour, minutes=random.randint(0, 59))
                log_rows.append(normal_event(user, ts))

            if random.random() < ATTACK_RATE:
                attack_type = random.choice(list(ATTACK_INJECTORS.keys()))
                attack_ts = day_date + timedelta(
                    hours=random.randint(0, 23), minutes=random.randint(0, 59)
                )
                ATTACK_INJECTORS[attack_type](user, attack_ts, log_rows)

    df = pd.DataFrame(log_rows)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = generate()
    out_path = "data/synthetic_access_logs.csv"
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} log rows for {NUM_USERS} users over {NUM_DAYS} days")
    print(f"Attack breakdown:\n{df[df['is_attack']==1]['attack_type'].value_counts()}")
    print(f"Saved to {out_path}")