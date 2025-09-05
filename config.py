import os

class Config:
    DATABASE_URL = "postgresql://tasks_online_db_v878_user:RQqQwxWao2uJBzS8j1O8fDwuEuwQnzcO@dpg-d2tl21ndiees738bsb3g-a:5432/tasks_online_db_v878"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "a4bc9ded472bf5s4d5f4s54f88e74rw41sd59t"
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "793db7be3b7ch4t85g4u8x5sd476fsd5j47y8j"
    
    















