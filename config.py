import os

class Config:
    DATABASE_URL = "sqlite:///react-tasks-online.db"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "supersecretkey"
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "jwtsecretkey"
