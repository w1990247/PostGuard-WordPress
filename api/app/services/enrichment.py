from api.app.services.ml_features import(SENSITIVE_FILES,normalisePath,fileName,fileExt,pathDepth,inSensitiveDir)
from api.app.services.correlation import bucketDirectory

def friendlyLocation(path:str | None,directory: str|None)-> str:

    raw= (path or directory or "").replace("\\","/").strip()

    if not raw:
        return "Unknown"
    
    lower=raw.lower()

    if "/wp-content/plugins/" in lower:
        rel= raw.split("/wp-content/plugins/",1)[1]
        return f"Plugins {rel}"

    if "/wp-content/themes/" in lower:
        rel= raw.split("/wp-content/themes/",1)[1]
        return f"Themes {rel}"

    if "/wp-content/uploads/" in lower:
        rel= raw.split("/wp-content/uploads/",1)[1]
        return f"Uploads {rel}"
    
    if "/wp-content/" in lower:
        rel= raw.split("/wp-content/",1)[1]
        return f"Content {rel}"
    
    
    if "/wp-admin/" in lower:
        rel= raw.split("/wp-admin/",1)[1] if "/wp-admin/" in lower else raw
        return f"Core admin {rel}"
    
    if "/wp-includes/" in lower:
        rel= raw.split("/wp-includes/",1)[1] if "/wp-includes/" in lower else raw
        return f"Core includes {rel}"
    
    return raw


def fallbackEventLocation(event_type:str|None, meta: dict|None =None)->str:
    event_type=(event_type or "").strip().lower()
    meta = meta or{}

    if event_type == "login":
        return "Wordpress login"
    
    if event_type =="profile_update":
        target_user_id=meta.get("target_user_id")
        return f"User profile {target_user_id}" if target_user_id else "User profile"
    
    if event_type in {"user_register", "user_delete", "role_change"}:
        target_user_id=meta.get("target_user_id")
        return f"User management {target_user_id}" if target_user_id else "User management"
    
    if event_type in {"post_edit","post_delete"}:
        post_type=meta.get("post_type") or "content"
        post_id= meta.get("post_id")
        return f"Content {post_type} {post_id}" if post_id else f"Content {post_type}"
    
    if event_type == "upgrader_completed":
        hook_extra =meta.get("hook_extra") or {}

        if hook_extra.get("plugin"):
            return f"Plugins {hook_extra['plugin']}"
        
        if hook_extra.get("theme"):
            return f"Themes {hook_extra['theme']}"
        
        return "Updater"
    

    if event_type == "theme_switched":
        theme_slug =meta.get("new_theme_slug") or meta.get("new_theme")
        return f"Themes {theme_slug}" if theme_slug else "Themes"
    
    if event_type in {"plugin_activated", "plugin_deactivated"}:
        plugin =meta.get("plugin")
        return f"Plugins {plugin}" if plugin else "Plugins"

    return "Unknown"
# This code adds extra context to events.
def enrichEventContext(path:str | None, directory: str | None, source: str | None, meta: dict |None=None)->dict:
    path_value = normalisePath(path)
    directory_value=normalisePath(directory)
    payload = dict(meta or {})

    payload["fileName"] = fileName(path_value)
    payload["fileExt"] = fileExt(path_value)
    payload["pathDepth"] = pathDepth(path_value)
    payload["bucketDirectory"] = bucketDirectory(directory_value)
    payload["isSensitiveFile"] = payload["fileName"] in SENSITIVE_FILES
    payload["isSensitiveDir"] = inSensitiveDir(path_value or directory_value)
    payload["sourceCategory"] = (source or "").strip().lower()

    return payload