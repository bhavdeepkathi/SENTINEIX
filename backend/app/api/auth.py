from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.core.database import get_db
from app.core.security import verify_password, get_password_hash, create_access_token
from app.core.dependencies import get_current_user
from app.models.user import User, Role
from app.schemas.auth import UserCreate, UserRead, Token

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    redirect_slashes=False,
)

@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    # check if email exists
    result = await db.execute(select(User).where(User.email == user_in.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # ensure default role exists
    role_result = await db.execute(select(Role).where(Role.name == "analyst"))
    role = role_result.scalar_one_or_none()
    if not role:
        role = Role(name="analyst")
        db.add(role)
        await db.flush()          # assign PK without committing the whole tx

    hashed_pw = get_password_hash(user_in.password)
    user = User(email=user_in.email, hashed_password=hashed_pw, role_id=role.id)
    db.add(user)
    await db.commit()
    # reload user with role eagerly loaded
    result = await db.execute(select(User).options(selectinload(User.role)).where(User.id == user.id))
    user = result.scalar_one()
    return UserRead(id=user.id, email=user.email, is_active=user.is_active, role=user.role.name)

@router.post("/login", response_model=Token)
async def login(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).options(selectinload(User.role)).where(User.email == user_in.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")
    access_token = create_access_token({"sub": user.email, "role": user.role.name})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserRead)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserRead(id=current_user.id, email=current_user.email, is_active=current_user.is_active, role=current_user.role.name)