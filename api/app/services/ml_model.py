import os
import pickle
from api.app.core.settings import settings
from api.app.services.ml_features import FEATURE_ORDER, extractMLFeatures,vectoriseFeatures

# This function loads the saved local scoring model.
def loadModelBundle() ->dict | None:
    path =settings.ML_MODEL_PATH

    if not os.path.exists(path):
        return None
    
    with open(path,"rb") as i:
        bundle =pickle.load(i)

    if bundle.get("feature_order") !=FEATURE_ORDER:
        return None
    
    return bundle


def predictMlRisk(
    *,
    event_type: str,
    path: str | None,
    source: str | None =None,
    meta: dict | None=None,
    actor_used_id: str|None=None,
)-> dict:
    features = extractMLFeatures(event_type=event_type,path=path,source=source,meta=meta,actor_user_id=actor_used_id
    )

    bundle =loadModelBundle()

    if bundle is None:
        return{
            "label": "allow",
            "confidence": 0.34,
            "probabilities": {"allow":0.34, "warn":0.33, "block": 0.33},
            "model_version": "missing-model",
            "features": features,
        }
    
    model=bundle["model"]
    class_names= bundle["class_names"]
    vector = [vectoriseFeatures(features)]

    probabilities_raw =model.predict_proba(vector)[0]
    probabilities ={class_names[index]:float(probabilities_raw[index]) for index in range(len(class_names))}
    label = max(probabilities, key=probabilities.get)

    return {
        "label": label,
        "confidence": probabilities[label],
        "probabilities":probabilities,
        "model_version":bundle.get("version", "unknown"),
        "features":features,
    }


