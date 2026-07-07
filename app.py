import os
import hashlib
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, session, abort

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

def hash_password(password):
    """使用 SHA-256 加盐哈希存储密码"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${pwd_hash}"


def check_password(password, stored):
    """验证密码"""
    salt, pwd_hash = stored.split("$")
    return hashlib.sha256((salt + password).encode()).hexdigest() == pwd_hash


# 预置用户（密码已哈希）
USERS = {
    "admin": {
        "username": "admin",
        "password": hash_password("Admin@2025#Secure"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": hash_password("Alice@2025#Secure"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def login_required(f):
    """登录校验装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


@app.route("/")
@login_required
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username].copy()
        # 前端不展示密码
        user_info.pop("password", None)
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username and password:
            user = USERS.get(username)
            if user and check_password(password, user["password"]):
                session.permanent = True
                session["username"] = username
                user_info = user.copy()
                user_info.pop("password", None)
                return render_template("index.html", user=user_info)

        return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    old_pw = request.form.get("old_password")
    new_pw = request.form.get("new_password")
    confirm_pw = request.form.get("confirm_password")

    if not all([old_pw, new_pw, confirm_pw]):
        return render_template("index.html", user=USERS[session["username"]], error="请填写所有字段")
    if new_pw != confirm_pw:
        return render_template("index.html", user=USERS[session["username"]], error="两次密码不一致")
    if len(new_pw) < 8:
        return render_template("index.html", user=USERS[session["username"]], error="新密码至少8位")

    username = session["username"]
    user = USERS[username]
    if not check_password(old_pw, user["password"]):
        return render_template("index.html", user=user, error="原密码错误")

    user["password"] = hash_password(new_pw)
    return render_template("index.html", user=user, message="密码修改成功")


if __name__ == "__main__":
    print("⚠️ 首次部署请访问 /login 并修改默认密码！")
    app.run(debug=False, host="0.0.0.0", port=5000)
