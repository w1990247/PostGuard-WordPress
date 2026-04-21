import json
import os
from api.app.core.settings import settings
from api.app.services.audit_chain import sha256_hex

def verifyPair(log_path: str, root_path: str| None) -> dict:
    if not os.path.exists(log_path):
        return {
            "status": "skip",
            "ok":True,
            "lines_checked": 0,
            "message": f"{os.path.basename(log_path)} not found.",
        }
    

    prev_hash= "0" * 64
    lines_checked = 0
    last_hash = prev_hash

    with open(log_path, "r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped =raw_line.strip()

            if not stripped:
                continue

            try:
                row= json.loads(stripped)

            except json.JSONDecodeError:
                return {
                    "status": "fail",
                    "ok": False,
                    "lines_checked": lines_checked,
                    "message": f"Invalid JSON on audit line {line_number} in {os.path.basename(log_path)}.",
                }
            
            record = row.get("record")
            row_prev_hash= row.get("prev_hash")
            row_hash = row.get("hash")

            if row_prev_hash != prev_hash:

                return {
                    "status": "fail",
                    "ok": False,
                    "lines_checked": lines_checked,
                    "message": f"Hash chain mismatch at line {line_number} in {os.path.basename(log_path)}.",
                }
            
            canonical=json.dumps(record, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")
            expected_hash=sha256_hex((prev_hash + sha256_hex(canonical)).encode("utf-8"))
            if row_hash != expected_hash:
                return {
                    "status": "fail",
                    "ok": False,
                    "lines_checked": lines_checked,
                    "message": f"Compute hash mismatch at line {line_number} in {os.path.basename(log_path)}.",
                }
            
            prev_hash=row_hash
            last_hash= row_hash
            lines_checked +=1

    stored_root = None

    if root_path and os.path.exists(root_path):

        with open(root_path, "r",encoding="utf-8") as handle:
            stored_root = handle.read().strip() or None

    if stored_root and stored_root != last_hash:
        return {
            "status": "fail",
            "ok": False,
            "lines_checked": lines_checked,
            "message": f"Root hash life does not match the last chained hash for {os.path.basename(log_path)}.",
            "computed_root_hash": last_hash,
            "stored_root_hash": stored_root,
        }
    
    return {
        "status": "pass",
        "ok": True,
        "lines_checked": lines_checked,
        "message": f"Integrity check passed for {os.path.basename(log_path)}.",
        "computed_root_hash": last_hash,
        "stored_root_hash": stored_root or last_hash,

    }

# This function is used to compare hash values to confirm the integrity of audit logs.
def verifyAuditChain() ->dict:

    log_path= settings.AUDIT_LOG_PATH
    root_path = settings.AUDIT_ROOT_HASH_PATH
    backup_dir = settings.AUDIT_BACKUP_DIR

    current_result = verifyPair(log_path,root_path)

    if not current_result.get("ok"):
        current_result["backups_checked"]=0
        return current_result
    
    backup_results =[]

    if backup_dir and os.path.isdir(backup_dir):
        backup_logs=sorted(
            name for name in os.listdir(backup_dir)
            if name.startswith("audit_") and name.endswith(".jsonl")

        )

        for backup_name in backup_logs:
            backup_log = os.path.join(backup_dir,backup_name)
            backup_root= os.path.join(backup_dir,backup_name.replace(".jsonl",".root.txt"))
            result = verifyPair(backup_log, backup_root)
            backup_results.append(
                {
                    "file": backup_name,
                    "ok": result.get("ok", False),
                    "lines_checked": result.get("lines_checked",0),
                    "message": result.get("message"),

                }
            )

            if not result.get("ok"):
                return {
                    "status": "fail",
                    "ok": False,
                    "lines_checked": current_result.get("lines_checked", 0),
                    "message": f"Backup audit verification failed for {backup_name}.",
                    "backups_checked": len(backup_results),
                    "backup_results": backup_results,
                }
            
    return {
        "status": "pass",
        "ok":True,
        "lines_checked": current_result.get("lines_checked", 0),
        "message": "Audit log integrity check passed.",
        "computed_root_hash": current_result.get("computed_root_hash"),
        "stored_root_hash": current_result.get("stored_root_hash"),
        "backups_checked": len(backup_results),
        "backup_results": backup_results,
    }


        