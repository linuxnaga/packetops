from fastapi import APIRouter

from . import auth, captures, f5, findings, workspace

api_router = APIRouter(prefix="/api/v1")
for module in (auth, captures, findings, f5, workspace):
    api_router.include_router(module.router)
