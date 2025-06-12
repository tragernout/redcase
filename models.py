from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin  # импорт UserMixin
from datetime import datetime, UTC

db = SQLAlchemy()

class User(db.Model, UserMixin):  # наследуем UserMixin
    __tablename__ = 'Users'

    uuid = db.Column(db.String, primary_key=True)
    nickname = db.Column(db.String, nullable=False)
    first_name = db.Column(db.String, nullable=True)
    last_name = db.Column(db.String, nullable=True)
    email = db.Column(db.String, nullable=True)
    telegram = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    solved_vms = db.Column(db.Integer, nullable=False)
    first_bloods = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    profile_description = db.Column(db.String, nullable=True)
    invite_code = db.Column(db.String, nullable=False)
    used_invite_code = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False)
    is_creator = db.Column(db.Boolean, nullable=False)
    vpn_config = db.Column(db.String, nullable=True)

    def get_id(self):
        return self.uuid


class VirtualMachine(db.Model):
    __tablename__ = 'VirtualMachines'

    uuid = db.Column(db.String, primary_key=True)
    name = db.Column(db.String, nullable=False)
    flag = db.Column(db.String, nullable=False)
    platform = db.Column(db.String, nullable=False)  # 'Windows' или 'Linux'
    difficulty = db.Column(db.Integer, nullable=False)  # 1–5
    description = db.Column(db.Text, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String, nullable=False)
    solve_count = db.Column(db.Integer, default=0)
    first_blood_uuid = db.Column(db.String, nullable=True)
    author_uuid = db.Column(db.String, nullable=False)


class Pwn(db.Model):
    __tablename__ = 'Pwns'

    uuid = db.Column(db.String, primary_key=True)
    user_uuid = db.Column(db.String, nullable=False)
    vm_uuid = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(UTC))