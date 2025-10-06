import os

class Config:
    DATABASE_URL = "postgresql://task_docket_db_user:F1nmYKc4C6QVgK66shdoV5ioceBtOWla@dpg-d3hughe3jp1c73fs9ln0-a/task_docket_db"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "a4bc9ded472bf5s4d5f4s54f88e74rw41sd59t"
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "793db7be3b7ch4t85g4u8x5sd476fsd5j47y8j"
    
    
















