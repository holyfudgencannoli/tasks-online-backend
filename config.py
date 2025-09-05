import os

class Config:
    DATABASE_URL = "postgresql://tasks_online_db_user:PmcrEw9xtnnzy5bEdhSjOaIwSVrC9KnT@dpg-d2t65puuk2gs73ci59v0-a/tasks_online_db"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "supersecretkey"
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "jwtsecretkey"



