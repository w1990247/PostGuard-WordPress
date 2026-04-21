from api.app.db.models import RiskScoring
from api.app.services.ml_model import predictMlRisk


RISK_ORDER={
    RiskScoring.allow: 0,
    RiskScoring.warn: 1,
    RiskScoring.block: 2,
}

FILE_CHANGE_EVENTS ={"create", "modify", "delete", "rename"}
WP_ADMIN_EVENTS = {"plugin_activated", "plugin_deactivated", "theme_switched","upgrader_completed"}
WP_CONTENT_EVENTS= {"upload","delete_attachment", "post_delete"}

ML_WARN_THRESHOLD=0.75
ML_BLOCK_THRESHOLD=0.90

def is_media_upload(path_value: str)->bool:
    medisExts= (".jpg",".jpeg", ".png", ".gif",".webp",".svg",".pdf",".doc",".docx",".txt",".csv")
    return "/wp-content/uploads/" in path_value and any(path_value.endswith(ext) for ext  in medisExts)

def has_corroborating_signals(event_type:str,path_value:str,meta:dict)->bool:
    event_type=(event_type or "").lower()
    burst_count= int(meta.get("burst_count", 0)or 0)

    if burst_count>4:
        return True
    
    if event_type in FILE_CHANGE_EVENTS and path_value.endswith(".php"):
        return  True
    
    if path_value.endswith((".zip",".rar",".7z")):
        return True


    if any(name in path_value for name in["wp-config.php","functions.php",".env"]):
        return True
    
    return False
#This code keeps the higher risk rating of the two.
def stronger_risk(a:RiskScoring,b:RiskScoring)-> RiskScoring:
    return a if RISK_ORDER[a] >= RISK_ORDER[b] else b

# This code applies the rule-based risk checks.
def rule_score_events(event_type:str, path: str|None, source:  str|None = None, meta:  dict|None = None)->tuple[RiskScoring, str]:

    path_value = (path or "").lower()
    eventType = (event_type or "").lower()
    source =(source or "").lower()
    meta =meta or {}
    sensitiveFiles =["wp-config.php", "functions.php", ".env"]
    sensitiveDirs = ["wp-content/plugins/", "wp-content/themes/", "wp-admin/", "wp-includes/"]

    if eventType == "delete" and any(part in path_value for part in sensitiveFiles):
        return RiskScoring.block, "Sensitive WordPress file deleted."
    

    if eventType in {"modify", "rename"} and any(part in path_value for part in sensitiveFiles):
        return RiskScoring.block, "Sensitive WordPress file changed."
    
    if eventType in {"modify","rename"} and path_value.endswith(".php") and any(part in path_value for part in sensitiveDirs):
        return RiskScoring.warn, "PHP change detected in a sensitive WordPress directory."
    
    # Normal admin actions stay low-risk unless other signals raise concern.
    if source=="wp_sensor" and eventType in WP_ADMIN_EVENTS:

        if has_corroborating_signals(event_type,path_value,meta):
            return RiskScoring.warn, "Administrative WordPress change was corroborated by other signals."

        return RiskScoring.allow, "Administrative WordPress change was detected without additional suspicious signals."


    if source=="wp_sensor" and eventType in WP_CONTENT_EVENTS:

        if has_corroborating_signals(event_type,path_value,meta):
            return RiskScoring.warn, "Content-related action was corroborated by other suspicious signals."

        if is_media_upload(path_value):
            return RiskScoring.allow, "Normal media-library activity detected."
        
        return RiskScoring.allow, "Normal WordPress content activity detected."

    if source =="wp_sensor" and eventType in {"role_change","user_delete"}:
        return RiskScoring.warn, "Sensitive WordPress administrative action was detected."
    

    if int(meta.get("burst_count", 0) or 0)>4:
        return RiskScoring.warn, "Rapid burst of file changes detected."
    
    if path_value.endswith((".zip",".rar",".7z")):
        return RiskScoring.warn, "Archive upload or movement detected."
    
    return RiskScoring.allow, "No high-risk rule matched."    


def score_events(event_type:str, path: str|None, source:  str|None = None, meta:  dict|None = None, actor_user_id: str | None=None,) -> tuple[RiskScoring,str]:
    
    meta =meta or {}

    rule_rating, rule_reason= rule_score_events(event_type,path,source,meta)
    ml_result = predictMlRisk(event_type=event_type,path=path,source=source,meta=meta,actor_used_id=actor_user_id,)
    ml_rating = RiskScoring(ml_result["label"])
    ml_confidence =float(ml_result["confidence"])
    path_value =(path or"").lower()
    event_type_value=(event_type or "").lower()
    sensitive_block_paths ={"wp-config.php","functions.php",".env"}
    is_sensitive_file_block_case=(event_type_value in {"modify","rename" ,"delete"}
        and any(name in path_value for name in sensitive_block_paths))
    #Weak model predictions are ignored.
    if ml_rating==RiskScoring.block and ml_confidence < ML_BLOCK_THRESHOLD:
        ml_rating =RiskScoring.allow

    elif ml_rating==RiskScoring.warn and ml_confidence < ML_WARN_THRESHOLD:
        ml_rating =RiskScoring.allow
    #Block is only allowed for clear sensitive file-tampering cases.
    if ml_rating==RiskScoring.block and not is_sensitive_file_block_case:
        ml_rating =RiskScoring.allow

    final_rating = stronger_risk(rule_rating,ml_rating)

    if final_rating == RiskScoring.block:

        if rule_rating == RiskScoring.block:
            return final_rating, f"{rule_reason} Boosted-tree confidence={ml_result['confidence']:.2f}."
        
        return final_rating, f"Boosted-tree model predicted block-worthy activity (confidence={ml_result['confidence']:.2f})."


    if final_rating == RiskScoring.warn:

        if rule_rating == RiskScoring.warn:
            return final_rating, f"{rule_reason} Boosted-tree confidence={ml_result['confidence']:.2f}."
        
        return final_rating, f"Boosted-tree model predicted suspicious activity (confidence={ml_result['confidence']:.2f})."
    
    return RiskScoring.allow, f"No risk pattern matched. Boosted-tree model confidence={ml_result['confidence']:.2f}."