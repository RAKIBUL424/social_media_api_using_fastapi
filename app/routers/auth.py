from fastapi import FastAPI, Response, status, HTTPException, Depends, APIRouter
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from ..database import get_db
from sqlalchemy.orm import Session
from .. import schemas, models, utils, oauth2

router = APIRouter(prefix="/login", tags=["Authentication"])

@router.post("/", status_code=status.HTTP_200_OK, response_model=schemas.Token)
def login(user: OAuth2PasswordRequestForm = Depends(),db: Session = Depends(get_db)):
    db_user = db.query(models.Users).filter(models.Users.email == user.username).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid Credentials")
    
    if not utils.verify(user.password, db_user.password):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid Credentials")
    
    access_token = oauth2.create_access_token(data={"user_id": db_user.id})
    
    return {"access_token": access_token, "token_type": "bearer"}