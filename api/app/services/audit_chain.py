import hashlib
import json
import os
import shutil
from datetime import datetime,timezone
from api.app.core.settings import settings

def sha256_hex(bytes1: bytes)-> str:

    return hashlib.sha256(bytes1).hexdigest()

class AuditChainWrite:

    def __init__(self):

        self.log_path= settings.AUDIT_LOG_PATH
        self.root_hash_path= settings.AUDIT_ROOT_HASH_PATH
        self.backup_dir = settings.AUDIT_BACKUP_DIR
        self.rotate_max_bytes = int(settings.AUDIT_ROTATE_MAX_BYTES or 0)
        self.backup_count = max(int(settings.AUDIT_BACKUP_COUNT or 0),0)

        log_dir = os.path.dirname(self.log_path)
        root_dir = os.path.dirname(self.root_hash_path)

        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        if root_dir:
            os.makedirs(root_dir, exist_ok=True)

        if self.backup_dir:
            os.makedirs(self.backup_dir, exist_ok=True)

    def read_hash(self)->str:

        if os.path.exists(self.root_hash_path):
            
            with open(self.root_hash_path,"r",encoding="utf-8") as i:
                return i.read().strip() or "0"*64
        
        return "0"*64
    
    def write_hash(self, hash1: str)-> None:
        root_dir =os.path.dirname(self.root_hash_path)
        if root_dir:
            os.makedirs(root_dir,exist_ok=True)

        with open(self.root_hash_path,"w",encoding="utf-8") as i:
            i.write(hash1)


    def rotation_needed(self)-> bool:

        if not self.rotate_max_bytes or self.rotate_max_bytes <=0:
            return False

        if not os.path.exists(self.log_path):
            return False
        
        try:
            return os.path.getsize(self.log_path) >= self.rotate_max_bytes
        except OSError:
            return False
        
    def cleanup_backups(self)->None:
        if not self.backup_dir or self.backup_count <= 0:
            return
        
        items = sorted(
            (
                os.path.join(self.backup_dir, name)
                for name in os.listdir(self.backup_dir)
                if name.startswith("audit_")

            ),

            key=lambda path: os.path.getmtime(path),
            reverse=True,

        )

        keep= self.backup_count *2

        for old_path in items[keep:]:

            try:
                os.remove(old_path)
            except OSError:
                pass

    #The function below rotates the log before it grows too large.
    def rotateIfNeeded(self) -> None:

        if not self.rotation_needed():
            return
        
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log_backup = os.path.join(self.backup_dir, f"audit_{stamp}.jsonl")
        root_backup = os.path.join(self.backup_dir, f"audit_{stamp}.root.txt")

        if os.path.exists(self.log_path):
            shutil.copy2(self.log_path, log_backup)

        if os.path.exists(self.root_hash_path):
            shutil.copy2(self.root_hash_path, root_backup)

        with open(self.log_path, "w", encoding="utf-8"):
            pass

        self.write_hash("0" * 64)
        self.cleanup_backups()
    # This code appends each audit record to a forward hash chain.
    def append(self, record:dict) -> str:
        self.rotateIfNeeded()
        prev=self.read_hash()
        canonical = json.dumps(record,sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")
        hash2= sha256_hex((prev + sha256_hex(canonical)).encode("utf-8"))
        line={"ts":datetime.now(timezone.utc).isoformat(),"record":record, "prev_hash":prev, "hash":hash2}

        with open(self.log_path, "a",encoding="utf-8")as i:
            i.write(json.dumps(line,ensure_ascii=False)+"\n")
        self.write_hash(hash2)
        return hash2
