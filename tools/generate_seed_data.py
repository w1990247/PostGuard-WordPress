import csv
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from api.app.services.ml_features import FEATURE_ORDER,extractMLFeatures

OUTPUT = ROOT / "data" / "ml_training_seed.csv"
RNG = random.Random(42)

SAFE_UPLOADS =[
    "/var/www/html/wp-content/uploads/2026/01/image.jpg",
    "/var/www/html/wp-content/uploads/2026/01/report.pdf",
    "/var/www/html/wp-content/uploads/2026/01/notes.txt",
    "/var/www/html/wp-content/uploads/2026/01/logo.png",
]

WARN_PLUGIN_FILES =[
    "/var/www/html/wp-content/plugins/postguard-sensor/postguard-sensor.php",
    "/var/www/html/wp-content/plugins/sample-plugin/admin.php",
    "/var/www/html/wp-content/themes/twentytwentyfour/functions.php",
]

BLOCK_CORE_FILES =[
    "/var/www/html/wp-config.php",
    "/var/www/html/wp-content/themes/twentytwentyfour/functions.php",
    "/var/www/html/wp-includes/pluggable.php",
    "/var/www/html/wp-admin/admin.php",
]
#This function is used to generate labelled seed events for local model training.
def allowEvent():
    choice =RNG.choice(["login","profile_update","post_edit","upload","safe_create" ])

    if choice == "login":
        return{
            "event_type": "login",
            "path": None,
            "source": "wp_sensor",
            "actor_user_id": str(RNG.randint(2,15)),
            "meta": {"burst_count": 0},
            "label": "allow",
        }
    
    if choice == "profile_update":
        return{
            "event_type": "profile_update",
            "path": None,
            "source": "wp_sensor",
            "actor_user_id": str(RNG.randint(2,15)),
            "meta": {"burst_count": 0},
            "label": "allow",
        }
    
    if choice == "post_edit":
        return{
            "event_type": "post_edit",
            "path": "/var/www/html/wp-content/uploads/2026/01/post-body.txt",
            "source": "wp_sensor",
            "actor_user_id": str(RNG.randint(2,15)),
            "meta": {"burst_count": RNG.choice([0,1])},
            "label": "allow",
        }
    

    if choice == "upload":
        return{
            "event_type": "upload",
            "path": RNG.choice(SAFE_UPLOADS),
            "source": "wp_sensor",
            "actor_user_id": str(RNG.randint(2,15)),
            "meta": {"burst_count": 0},
            "label": "allow",
        }
    
    return{
        "event_type": "create",
        "path": "/var/www/html/wp-content/uploads/2026/01/readme.txt",
        "source": "watcher",
        "actor_user_id": None,
        "meta": {"burst_count": RNG.choice([0,1])},
        "label": "allow",
    }
    
    
def warnEvent():
    choice =RNG.choice(["plugin_php","burst_modify","zip_upload","role_change","delete_attachment"])

    if choice == "plugin_php":
        return{
            "event_type": RNG.choice(["create","modify","rename"]),
            "path": RNG.choice(WARN_PLUGIN_FILES),
            "source": "watcher",
            "actor_user_id": None,
            "meta": {"burst_count": RNG.choice([1,2,3])},
            "label": "warn",
        }
    
    if choice == "burst_modify":
        return{
            "event_type": "modify",
            "path":"/var/www/html/wp-content/plugins/sample-plugin/class-admin.php",
            "source": "watcher",
            "actor_user_id": None,
            "meta": {"burst_count": RNG.choice([4,5,6])},
            "label": "warn",
        }
    
    if choice == "zip_upload":
        return{
            "event_type": "upload",
            "path":"/var/www/html/wp-content/uploads/2026/01/plugin-package.zip",
            "source": "wp_sensor",
            "actor_user_id": str(RNG.randint(2,25)),
            "meta": {"burst_count": 0},
            "label": "warn",
        }
    

    if choice == "role_change":

        return{
            "event_type": "role_change",
            "path":None,
            "source": "wp_sensor",
            "actor_user_id": str(RNG.randint(1,10)),
            "meta": {"burst_count": 0},
            "label": "warn",
        }
    
        
    return{

        "event_type": "delete_attachment",
        "path":RNG.choice(SAFE_UPLOADS),
        "source": "wp_sensor",
        "actor_user_id": str(RNG.randint(2,25)),
        "meta": {"burst_count": 0},
        "label": "warn",
    }


def blockEvent():
    choice =RNG.choice(["delete_sensetive","modify_sensetive","core_php_create", "rename_core"])


    if choice == "delete_sensetive":

        return{
            "event_type": "delete",
            "path":RNG.choice(BLOCK_CORE_FILES),
            "source": "watcher",
            "actor_user_id": None,
            "meta": {"burst_count": RNG.choice([0,1,2])},
            "label": "block",
        }
    
    if choice == "modify_sensetive":

        return{
            "event_type": RNG.choice(["modify", "rename"]),
            "path":RNG.choice(BLOCK_CORE_FILES),
            "source": "watcher",
            "actor_user_id": None,
            "meta": {"burst_count": RNG.choice([1,2,3])},
            "label": "block",
        }
    
    if choice == "core_php_create":

        return{
            "event_type": "create",
            "path":"/var/www/html/wp-admin/evil-shell.php",
            "source": "watcher",
            "actor_user_id": None,
            "meta": {"burst_count": RNG.choice([2,3,4])},
            "label": "block",
        }
    

    return{
        "event_type": "rename",
        "path":"/var/www/html/wp-includes/class-wp-hook.php",
        "source": "watcher",
        "actor_user_id": None,
        "meta": {"burst_count": RNG.choice([1,2]),"old_path":"/var/www/html/wp-includes/class-wp-hook-old.php"},
        "label": "block",
    }


def main():
    OUTPUT.parent.mkdir(parents=True,exist_ok=True)

    rows=[]

    for _ in range(180):
        rows.append(allowEvent())

    for _ in range(180):
        rows.append(warnEvent())

    for _ in range(180):
        rows.append(blockEvent())

    RNG.shuffle(rows)

    with open(OUTPUT,"w",encoding="utf-8",newline="") as h:
        writer = csv.DictWriter(h,fieldnames=FEATURE_ORDER +["label"])
        writer.writeheader()


        for row in rows:
            features =extractMLFeatures(event_type=row["event_type"], path=row["path"], source=row["source"], meta=row["meta"], actor_user_id=row["actor_user_id"],)

            output={name:features[name] for name in FEATURE_ORDER}
            output["label"]= row["label"]
            writer.writerow(output)

    
    print(f"Wrote {len(rows)} rows to {OUTPUT}")


if __name__ == "__main__":
    main()


        