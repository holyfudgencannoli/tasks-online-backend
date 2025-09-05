import os

class Config:
    DATABASE_URL = "postgresql://tasks_online_db_user:PmcrEw9xtnnzy5bEdhSjOaIwSVrC9KnT@dpg-d2t65puuk2gs73ci59v0-a:5432/tasks_online_db"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "01991b9b-702a-7285-8602-1ca7fd5c099f-7b10-b1c9-a7b6b5e47723-7f1c-9370-793db7be3b7c"
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or "01991b9b-702a-717c-aa8d-a4bc9ded472b-702a-7b5f-a957-fff42434abb3-702a-77ac-8611-0bdd6734ba35"














