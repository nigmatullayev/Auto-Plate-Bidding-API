from fastapi import FastAPI, Depends, HTTPException, status,Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional,List
from sqlalchemy.orm import Session
from backend.app.database import SessionLocal, engine
from backend.app.models import Base, User, AutoPlate, Bid
from backend.app.schemas import UserCreate, AutoPlateCreate, BidCreate
from fastapi.middleware.cors import CORSMiddleware

# Initialize FastAPI app
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (for development only)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

SECRET_KEY = "ahmadjon"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_admin(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admins can perform this action")
    return current_user

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/plates/", response_model=AutoPlateCreate)
def create_plate(plate: AutoPlateCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Only admins can create plates")
    db_plate = AutoPlate(
        plate_number=plate.plate_number,
        description=plate.description,
        deadline=plate.deadline,
        created_by=current_user.id,
    )
    db.add(db_plate)
    db.commit()
    db.refresh(db_plate)
    return db_plate

@app.get("/plates/", response_model=List[AutoPlateCreate])
def list_plates(
    skip: int = 0,
    limit: int = 10,
    ordering: Optional[str] = Query(None, description="Sort by 'deadline' or '-deadline'"),
    plate_number_contains: Optional[str] = Query(None, description="Filter by plate number containing"),
    db: Session = Depends(get_db),
):
    query = db.query(AutoPlate).filter(AutoPlate.is_active == True)

    # Filter by plate number
    if plate_number_contains:
        query = query.filter(AutoPlate.plate_number.contains(plate_number_contains))

    # Sort by deadline
    if ordering == "deadline":
        query = query.order_by(AutoPlate.deadline.asc())
    elif ordering == "-deadline":
        query = query.order_by(AutoPlate.deadline.desc())

    plates = query.offset(skip).limit(limit).all()
    return plates

@app.get("/plates/{plate_id}", response_model=AutoPlateCreate)
def get_plate(plate_id: int, db: Session = Depends(get_db)):
    plate = db.query(AutoPlate).filter(AutoPlate.id == plate_id).first()
    if not plate:
        raise HTTPException(status_code=404, detail="Plate not found")
    return plate

@app.put("/plates/{plate_id}", response_model=AutoPlateCreate)
def update_plate(plate_id: int, plate: AutoPlateCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_admin)):
    db_plate = db.query(AutoPlate).filter(AutoPlate.id == plate_id).first()
    if not db_plate:
        raise HTTPException(status_code=404, detail="Plate not found")
    db_plate.plate_number = plate.plate_number
    db_plate.description = plate.description
    db_plate.deadline = plate.deadline
    db.commit()
    db.refresh(db_plate)
    return db_plate

@app.delete("/plates/{plate_id}")
def delete_plate(plate_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_admin)):
    plate = db.query(AutoPlate).filter(AutoPlate.id == plate_id).first()
    if not plate:
        raise HTTPException(status_code=404, detail="Plate not found")
    if plate.bids:
        raise HTTPException(status_code=400, detail="Cannot delete plate with existing bids")
    db.delete(plate)
    db.commit()
    return {"message": "Plate deleted successfully"}

# Bid endpoints
@app.post("/bids/", response_model=BidCreate)
def place_bid(bid: BidCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    plate = db.query(AutoPlate).filter(AutoPlate.id == bid.plate_id).first()
    if not plate:
        raise HTTPException(status_code=404, detail="Plate not found")
    if plate.deadline < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Bidding is closed for this plate")
    existing_bid = db.query(Bid).filter(Bid.user_id == current_user.id, Bid.plate_id == bid.plate_id).first()
    if existing_bid:
        raise HTTPException(status_code=400, detail="You can only place one bid per plate")
    db_bid = Bid(
        amount=bid.amount,
        user_id=current_user.id,
        plate_id=bid.plate_id,
    )
    db.add(db_bid)
    db.commit()
    db.refresh(db_bid)
    return db_bid

app.get("/bids/")
def list_user_bids(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    bids = db.query(Bid).filter(Bid.user_id == current_user.id).all()
    return bids

@app.put("/bids/{bid_id}", response_model=BidCreate)
def update_bid(bid_id: int, bid: BidCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_bid = db.query(Bid).filter(Bid.id == bid_id).first()
    if not db_bid:
        raise HTTPException(status_code=404, detail="Bid not found")
    if db_bid.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only update your own bids")
    plate = db.query(AutoPlate).filter(AutoPlate.id == db_bid.plate_id).first()
    if plate.deadline < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Cannot update bid after deadline")
    db_bid.amount = bid.amount
    db.commit()
    db.refresh(db_bid)
    return db_bid

@app.delete("/bids/{bid_id}")
def delete_bid(bid_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    bid = db.query(Bid).filter(Bid.id == bid_id).first()
    if not bid:
        raise HTTPException(status_code=404, detail="Bid not found")
    if bid.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own bids")
    plate = db.query(AutoPlate).filter(AutoPlate.id == bid.plate_id).first()
    if plate.deadline < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Cannot delete bid after deadline")
    db.delete(bid)
    db.commit()
    return {"message": "Bid deleted successfully"}