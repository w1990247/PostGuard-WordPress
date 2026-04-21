import os,time,json,hmac,hashlib
from datetime import datetime, timezone
import requests
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler


API_URL= os.getenv("PG_API_URL","http://caddy/api/events/ingest")
API_KEY_ID= os.getenv("PG_API_KEY_ID","")
API_KEY_SECRET= os.getenv("PG_API_KEY_SECRET","")
WATCH_PATHS_RAW= os.getenv("PG_WATCH_PATHS", os.getenv("PG_WATCH_PATH", "."))
WATCHER_SCOPE_FILE= os.getenv("WATCHER_SCOPE_FILE", "/api/data/watcher_scope.json")
EVENT_COOLDOWN_SECONDS =float(os.getenv("PG_EVENT_COOLDOWN_SECONDS", "1.0"))
_RECENT = {}


def Sign(timestamp: int, body: bytes)-> str:

    message = f"{timestamp}.".encode("utf-8")+ body
    return hmac.new(API_KEY_SECRET.encode("utf-8"),message,hashlib.sha256).hexdigest()


def normalize(path: str)-> str:
    return os.path.abspath(path).replace("\\", "/")

# This code loads the current watcher scope.
def loadScope()-> dict:

    default_paths=[part.strip() for part in WATCH_PATHS_RAW.split(",") if part.strip()]
    scope = {"paths": default_paths, "ignore_paths": []}

    if not os.path.exists(WATCHER_SCOPE_FILE):
        return scope
    
    try:
        with open(WATCHER_SCOPE_FILE,"r", encoding="utf-8") as h:
            data=json.load(h)
        paths=[str(item).strip() for item in data.get("paths", []) if str(item).strip()]
        ignore_paths = [str(item).strip() for item in data.get("ignore_paths", []) if str(item).strip()]

        if paths:
            scope["paths"]=paths
        scope["ignore_paths"]=ignore_paths

    except Exception as exc:
        print ("Filed to load watcher scope file:",exc)

    return scope


def splitTargets(paths: list[str])->tuple[list[str], list[str],list[str]]:
    watched_dirs=[]
    watched_files = []
    schedule_dirs = set()

    for raw in paths:
        target =normalize(raw)

        if os.path.isdir(target):
            watched_dirs.append(target)
            schedule_dirs.add(target)

        elif os.path.isfile(target):
            watched_files.append(target)
            schedule_dirs.add(normalize(os.path.dirname(target)))

        else:
            watched_dirs.append(target)
            schedule_dirs.add(target)

    return watched_dirs,watched_files,sorted(schedule_dirs)



def shouldTrack(path:str, watched_dirs: list[str], watched_files: list[str], ignore_paths: list[str])->bool:

    value=normalize(path)

    for ignore in ignore_paths:
        ignore_norm = normalize(ignore)

        if value == ignore_norm or value.startswith(ignore_norm.rstrip("/") + "/"):
            return False
        
        
    for file_target in watched_files:
        if value == file_target:
            return True
        
    
    for dir_target in watched_dirs:
        if value == dir_target or value.startswith(dir_target.rstrip("/")+ "/"):
            return True
        
    return False


# This code reduces repeated file events from the same action.
def shouldEmit(event_type: str, path: str)-> bool:

    key= f"{event_type}:{normalize(path)}"
    now=time.time()
    last=_RECENT.get(key,0.0)

    if now - last< EVENT_COOLDOWN_SECONDS:
        return False
    
    _RECENT[key] =now

    if len(_RECENT) > 1000:
        cutoff = now -10
        stale =[k for k, v in _RECENT.items() if v < cutoff]

        for item in stale:
            _RECENT.pop(item, None)

    return True


# This code signs watcher events before sending them.
def PostEvent(event_type: str, path: str, watched_dirs: list[str], watched_files: list[str], ignore_paths: list[str], meta: dict | None=None):

    path =normalize(path)

    if not shouldTrack(path,watched_dirs,watched_files,ignore_paths):
        return
    
    if not shouldEmit(event_type,path):
        return

    payload= {

        "source": "watcher",
        "event_type": event_type,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "actor_user_id": None,
        "actor_user_name": None,
        "path": path,
        "directory": normalize(os.path.dirname(path)),
        "meta": meta or {},

        }
    
    body = json.dumps(payload).encode("utf-8")
    TimeStamp= int(datetime.now(timezone.utc).timestamp())
    Signature= Sign(TimeStamp,body)

    Request= requests.post(

        API_URL, data=body, headers={
            "Content-Type": "application/json",
            "X-PG-API-KEY": API_KEY_ID,
            "X-PG-TIMESTAMP": str(TimeStamp),
            "X-PG-SIGNATURE": Signature,
        },
        timeout=10

    )

    print("POST", event_type, path, "->",Request.status_code, Request.text[:120])

class Handler(FileSystemEventHandler):

    def __init__(self, watched_dirs: list[str], watched_files: list[str], ignore_paths: list[str]):
        self.watched_dirs =watched_dirs
        self.watched_files =watched_files
        self.ignore_paths = ignore_paths

    def on_created(self, event):

        if not event.is_directory:
            PostEvent("create", event.src_path, self.watched_dirs,self.watched_files,self.ignore_paths)

    
    def on_modified(self, event):
        
        if not event.is_directory:
            PostEvent("modify", event.src_path, self.watched_dirs,self.watched_files,self.ignore_paths)

    def on_deleted(self, event):
        
        if not event.is_directory:
            PostEvent("delete", event.src_path, self.watched_dirs,self.watched_files,self.ignore_paths)

    def on_moved(self, event):
        
        if not event.is_directory:
            PostEvent("rename", event.dest_path, self.watched_dirs, self.watched_files, self.ignore_paths, meta={"old_path":normalize(event.src_path)})


#The following function rebuilds the observer using the  latest scope.
def buildObserver(scope: dict):

    watched_dirs, watched_files, schedule_dirs = splitTargets(scope.get("paths",[]))
    ignore_paths = [normalize(item) for item in scope.get("ignore_paths", [])]
    use_poll = os.getenv("PG_WATCH_POLL", "0") == "1"
    observer = PollingObserver(timeout=1) if use_poll else Observer()
    handler = Handler(watched_dirs, watched_files, ignore_paths)

    print("Watching targets:")
    for path in watched_dirs + watched_files:
        print(" -",path)

    print("Scheduling directories:")
    for path in schedule_dirs:

        print(" -", path)

        if os.path.exists(path):
            observer.schedule(handler, path, recursive=True)

    observer.start()
    return observer


if __name__== "__main__":
    scope=loadScope()
    scope_signature = json.dumps(scope, sort_keys=True)
    observer=buildObserver(scope)

    try:
        while True:
            time.sleep(5)
            latest_scope =loadScope()
            latest_signature = json.dumps(latest_scope, sort_keys=True)

            if latest_signature != scope_signature:
                print("Watcher scope changed. Reloading observer.")
                observer.stop()
                observer.join()
                scope=latest_scope
                scope_signature=latest_signature
                observer=buildObserver(scope)
    
    except KeyboardInterrupt:

        observer.stop()
        observer.join()
