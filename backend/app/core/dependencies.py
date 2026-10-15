from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import decode_session
from app.db.database import get_db
from app.db.models import User

settings = get_settings()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(settings.COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "UNAUTHENTICATED", "message": "Not authenticated"})

    session = decode_session(token)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "INVALID_TOKEN", "message": "Session expired or invalid"})
    user_id, session_version = session

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "USER_NOT_FOUND", "message": "User no longer exists"})
    # Logout / password reset bump the user's session_version; older tokens are dead from then on.
    if session_version != int(user.session_version or 0):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": "SESSION_ENDED", "message": "Session ended. Please sign in again."})
    return user


def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    try:
        return get_current_user(request, db)
    except HTTPException:
        return None


def is_admin(user: User, db: Session) -> bool:
    """Who may use system-wide controls (automatic protection, alert channels).

    1. users with role "admin";
    2. otherwise, if ADMIN_EMAILS is set, exactly those accounts;
    3. otherwise the automation owner -- the account that receives automatic findings
       (AUTOMATION_USER_EMAIL, or the first account created). Any other account is a normal user.
    """
    s = get_settings()
    if (user.role or "").lower() == "admin":
        return True
    admins = s.admin_email_list
    if admins:
        return (user.email or "").lower() in admins
    from app.automation.engine import owner_user_id   # same rule the watchers use, so it always agrees
    return owner_user_id(db) == user.id


def require_admin(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    if not is_admin(user, db):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail={"error": {"code": "ADMIN_ONLY", "message": "Only the CyberGuard administrator can do this."}})
    return user
