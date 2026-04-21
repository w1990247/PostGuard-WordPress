from fastapi import FastAPI
from api.app.core.settings import settings
from api.app.core.redis_client import close_redis
from api.app.db.init_db import init_db
from api.app.db.session import LocalSession
from api.app.routers.health import router as health_router
from api.app.routers.ingest import router as ingest_router
from api.app.routers.auth import router as auth_router
from api.app.routers.incidents import router as incidents_router
from api.app.routers.invites import router as invites_router
from api.app.routers.users import router as user_router
from api.app.routers.config import router as config_router
from api.app.routers.audit import router as audit_router
from api.app.core.bootstrap import ensureBootStrap
from api.app.services.config_store import getOrCreateAlertPolicy,getOrCreateWatcherScope
from api.app.services.event_queue import startWorker,stopWorker,recoverStuckQueueItems


def create_app()->FastAPI:

    app= FastAPI(title="PostGuard-WordPress")
    app.include_router(health_router,prefix=settings.API_PREFIX)
    app.include_router(ingest_router,prefix=settings.API_PREFIX)
    app.include_router(auth_router, prefix=settings.API_PREFIX)
    app.include_router(incidents_router, prefix=settings.API_PREFIX)
    app.include_router(invites_router, prefix=settings.API_PREFIX)
    app.include_router(user_router, prefix=settings.API_PREFIX)
    app.include_router(config_router, prefix=settings.API_PREFIX)
    app.include_router(audit_router, prefix=settings.API_PREFIX)


    @app.on_event("startup")
    async def startup():
        init_db()
        db= LocalSession()

        try:
            ensureBootStrap(db)
            getOrCreateAlertPolicy(db)
            getOrCreateWatcherScope(db)
            recoverStuckQueueItems(db)

        finally:
            db.close()

        await startWorker()

    @app.on_event("shutdown")
    async def shutdown():
        await stopWorker()
        await close_redis()

    return app

app = create_app()