from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, JWTManager
from sqlalchemy import Column, Integer, String, ForeignKey, Float, Boolean, DateTime, create_engine, MetaData, Table
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from config import Config
from datetime import datetime


app = Flask(__name__)
app.config.from_object(Config)
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://10.0.0.45:5173"]}}, supports_credentials=True)
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in BLACKLIST

# Helper functions
def create_user(username, password_hash, email, phone, is_admin):
    db_session = SessionLocal()
    already_there = db_session.query(User).filter(User.username==username).first()

    if not already_there:
        user = User(
            username=username,
            email=email,
            is_admin=is_admin,
            phone=phone,
            password_hash=password_hash,
            provider="local"
        )

        db_session.add(user)
        db_session.commit()
    else:
        raise ValueError("User already exists")
    db_session.close()
    

def get_user_by_username(username):
    db_session = SessionLocal()
    user = db_session.query(User).filter_by(username=username).first()
    db_session.close()
    if user:
        # return consistent keys
        return {
            "id": user.id,
            "username": user.username,
            "password_hash": user.password_hash  # <-- must match table
        }
    return None

def check_password(user, password):
    if not user or "password_hash" not in user:
        return False
    return check_password_hash(user["password_hash"], password)




Base = declarative_base()


engine = create_engine(Config.DATABASE_URL, echo=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)



class User(Base):
    __tablename__ = 'users' 
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(150), unique=True, nullable=False)
    password_hash = Column(String(150), nullable=False)
    is_admin = Column(Boolean, default=False)
    email = Column(String)
    phone = Column(String)
    provider = Column(String)
    provider_id = Column(Integer)
    created_at = Column(DateTime)
    last_login =  Column(DateTime)
    tasks = relationship("Task", back_populates="user")

    def to_dict(self):
        return{
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'email': self.email,
            'phone': self.phone,
            'provider': self.provider,
            'provider_id': self.provider_id,
            'created_at': self.created_at,
            'last_login': self.last_login,
        }
    
    def get_id(self):
        return str(self.id)

class Task(Base):
    __tablename__ = 'tasks'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String)
    due_datetime = Column(String)
    log_datetime = Column(String)
    fin_datetime = Column(String)
    completed = Column(Boolean, default=False)
    memo = Column(String)

    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="tasks")


    def to_dict(self):
        return{
            'id': self.id,
            'name': self.name,
            'due_datetime': self.due_datetime,
            'log_datetime': self.log_datetime,
            'fin_datetime': self.fin_datetime,
            'completed': self.completed,
            'memo': self.memo,
        }


Base.metadata.create_all(bind=engine)



@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.form

    username = data.get('username')
    email = data.get('email')
    phone = data.get('phone')
    isAdmin = data.get('is_admin')

    if isAdmin == 'admin123':
        is_admin = True
    else:
        is_admin = False

    password_hash = generate_password_hash(data.get('password'))

    try:
        create_user(username, password_hash, email, phone, is_admin)
    except ValueError:
        return jsonify({"msg": "User already exists"}), 400
    return jsonify({"msg": "User created"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    user = get_user_by_username(data['username'])
    if user and check_password(user, data['password']):
        access_token = create_access_token(identity=str(user['id']))
        user_data = {"id": user["id"], "username": user["username"]}
        return jsonify({'access_token': access_token, 'user': user_data})
    return jsonify({"msg": "Bad username or password"}), 401

BLACKLIST = set()

@app.route("/api/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    BLACKLIST.add(jti)
    return jsonify(msg="Successfully logged out"), 200


@app.route('/api/log-tasks', methods=['POST'])
@jwt_required()
def log_task():
    db_session = SessionLocal()

    data = request.form

    name = data.get('name')
    due_datetime = data.get('due_datetime')
    log_datetime = data.get('log_datetime')
    fin_datetime = data.get('fin_datetime')
    completed = data.get('completed')
    memo = data.get('memo')
    user_id = data.get('user_id')

    new_task = Task(
        name=name,
        due_datetime=due_datetime,
        log_datetime=log_datetime,
        user_id=user_id
    )

    db_session.add(new_task)
    db_session.commit()

    new_task_dict = new_task.to_dict()
    db_session.close()


    return jsonify({'success': True, 'task': new_task_dict})


@app.route('/api/get-tasks-all', methods=['GET'])
def get_tasks_all():
    db_session = SessionLocal()

    tasks = db_session.query(Task).all()

    tasks_serialized = [t.to_dict() for t in tasks]
    db_session.close()
    return jsonify({'tasks': tasks_serialized})

@app.route('/api/get-tasks', methods=['POST'])
@jwt_required()
def get_tasks():
    data = request.get_json()

    date_str = data.get('date')

    target_date = datetime.strptime(date_str, "%Y-%m-%d").date()

    db_session = SessionLocal()

    tasks = []
    for t in db_session.query(Task).all():
        if t.log_datetime: 
            try:
                task_date = datetime.fromisoformat(t.log_datetime).date()
                if task_date == target_date:
                    tasks.append(t.to_dict())
            except ValueError:
                # optionally log invalid date strings
                print("Skipping invalid datetime:", t.log_datetime)
    db_session.close()

    return jsonify({'tasks': tasks})

@app.route('/api/get-tasks-to-do', methods=['GET'])
@jwt_required()
def get_tasks_to_do():
    db_session = SessionLocal()

    tt = db_session.query(Task).filter_by(completed=False).all()

    tasks = []
    for t in tt:
        tasks.append(t.to_dict())
    db_session.close()

    return jsonify({'tasks': tasks})

@app.route('/api/mark-complete', methods=['POST'])
@jwt_required()
def mark_complete():
    data = request.get_json()

    task_id = data.get('task_id')

    db_session = SessionLocal()

    task_obj = db_session.query(Task).filter_by(id=task_id).first() #type:ignore


    task_obj.completed = True
    task_obj.fin_datetime = datetime.now().isoformat()
    print(datetime.now().isoformat())

    db_session.commit()
    db_session.close()

    return jsonify({'message': 'Task marked complete!'})




if __name__ == '__main__':
    app.run(debug=True)
