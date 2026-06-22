from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.models.models import User
from app.schemas.schemas import UserResponse

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user
