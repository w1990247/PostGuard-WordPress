from sqlalchemy.orm import Session
from api.app.db import models
from api.app.core.settings import settings
from api.app.core.auth import hashPassword



def ensureUser(
        db:Session,
        *,
        email: str|None,
        password:str|None,
        display_name:str,
        role:models.UserRoles,
)-> None:
    if not email or not password:
        return
    
    clean_email = email.lower().strip()
    user= db.query(models.User).filter(models.User.email==clean_email).first()

    if user:
        return


    db.add(
        models.User(
            email= clean_email,
            display_name=display_name,
            password_hash=hashPassword(password),
            role=role,
            is_active=True,

        )
    )
    db.commit()


# The following code creates the initial admin and analyst accounts.
def ensureBootStrap(db: Session)-> None:

    ensureUser(
        db,
        email= settings.BOOTSTRAP_ADMIN_EMAIL,
        password=settings.BOOTSTRAP_ADMIN_PASSWORD,
        display_name="Admin",
        role=models.UserRoles.admin,
    )


    ensureUser(
        db,
        email= settings.BOOTSTRAP_ANALYST_EMAIL,
        password=settings.BOOTSTRAP_ANALYST_PASSWORD,
        display_name="Analyst",
        role=models.UserRoles.analyst,
    )
    