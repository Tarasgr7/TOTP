from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Base, User
from schemas import UserCreate, UserLogin
import bcrypt
import pyotp

app = FastAPI()

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register/")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Користувач вже існує")

    hashed_password = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    secret = pyotp.random_base32()

    db_user = User(username=user.username, hashed_password=hashed_password, secret=secret)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    totp = pyotp.TOTP(secret)
    otp_url = totp.provisioning_uri(user.username, issuer_name="FastAPI-TOTP")

    return {"message": "Користувач зареєстрований", "otp_url": otp_url}

@app.post("/login/")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first() 
    if not db_user:
        raise HTTPException(status_code=400, detail="Користувач не знайдений")

    if not bcrypt.checkpw(user.password.encode("utf-8"), db_user.hashed_password.encode("utf-8")):
        raise HTTPException(status_code=400, detail="❌ Неправильний пароль")

    # Перевірка OTP-коду
    totp = pyotp.TOTP(db_user.secret)
    if not totp.verify(user.otp_code):
        raise HTTPException(status_code=400, detail="❌ Неправильний TOTP-код")

    return {"message": "✅ Вхід успішний!"}


@app.get("/users/")
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()
