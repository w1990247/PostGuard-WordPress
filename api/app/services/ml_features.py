FEATURE_ORDER=[
    "is_create",
    "is_modify",
    "is_delete",
    "is_rename",
    "source_watcher",
    "source_wp_sensor",
    "has_actor",
    "has_old_path",
    "burst_count_norm",
    "path_depth_norm",
    "is_php",
    "is_zip",
    "is_sensitive_file",
    "is_sensitive_dir",
    "is_media_upload",
    "is_plugin_dir",
    "is_theme_dir",
    "is_core_dir",
]

SENSITIVE_FILES={
    "wp_config.php",
    "functions.php",
    ".env",
    "pluggable.php",
    "class-wp-hook.php",
}

MEDIA_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".pdf", ".doc", ".docx", ".txt", ".csv"

}

def toInt(value, default=0):
    try:

        return int(value)
    except Exception:
        return default
    

def normalisePath(path: str | None) -> str:
    return (path or "").replace("\\", "/").strip().lower()


def fileName(path: str|None)-> str:
    value= normalisePath(path)

    if not value:
        return ""
    return value.split("/")[-1]


def fileExt(path: str|None)-> str:
    name= fileName(path)

    if "." not in name:
        return ""
    return "." + name.split(".")[-1]


def pathDepth(path: str| None)->int:
    value =normalisePath(path)

    if not value:
        return 0
    return len([part for part in value.split("/") if part])

def inPluginDir(path: str|None) -> bool:
    value = normalisePath(path)
    return "/wp-content/plugins/" in value

def inThemeDir(path: str|None) -> bool:
    value = normalisePath(path)
    return "/wp-content/themes/" in value


def inCoreDir(path: str|None) -> bool:
    value = normalisePath(path)
    return "/wp-admin/" in value or "/wp-includes/" in value

def inSensitiveDir(path: str | None) -> bool:
    return inPluginDir(path) or inThemeDir(path) or inCoreDir(path)

#The following code turns event data into model features.
def extractMLFeatures(
    *,
    event_type: str,
    path: str | None,
    source: str | None =None,
    meta: dict | None = None,
    actor_user_id: str | None = None,)-> dict[str,float]:
    meta = meta or {}
    event_type = (event_type or "").strip().lower()
    source = (source or "").strip().lower()
    path_value=normalisePath(path)
    ext =fileExt(path_value)
    burst_count=toInt(meta.get("burst_count", 0),0)

    return{
        "is_create": 1.0 if event_type == "create" else 0.0,
        "is_modify": 1.0 if event_type == "modify" else 0.0,
        "is_delete": 1.0 if event_type == "delete" else 0.0,
        "is_rename": 1.0 if event_type == "rename" else 0.0,
        "source_watcher": 1.0 if source == "watcher" else 0.0,
        "source_wp_sensor": 1.0 if source == "wp_sensor" else 0.0,
        "has_actor": 1.0 if actor_user_id else 0.0,
        "has_old_path": 1.0 if meta.get("old_path") else 0.0,
        "burst_count_norm": min(burst_count,10) / 10.0,
        "path_depth_norm": min(pathDepth(path_value),12) / 12.0,
        "is_php": 1.0 if ext == ".php" else 0.0,
        "is_zip": 1.0 if ext in {".zip",".rar",".7z"} else 0.0,
        "is_sensitive_file": 1.0 if fileName(path_value) in SENSITIVE_FILES else 0.0,
        "is_sensitive_dir": 1.0 if inSensitiveDir(path_value) else 0.0,
        "is_media_upload": 1.0 if "/wp-content/uploads/" in path_value and ext in MEDIA_EXTS else 0.0,
        "is_plugin_dir": 1.0 if inPluginDir(path_value) else 0.0,
        "is_theme_dir": 1.0 if inThemeDir(path_value) else 0.0,
        "is_core_dir": 1.0 if inCoreDir(path_value) else 0.0,


    }

def vectoriseFeatures(features: dict[str, float])->list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_ORDER]
