import sqlite3
import os
import re
import time
import secrets
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, session, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# Flask 应用配置
# ============================================================

app = Flask(__name__)

# 密钥：优先从环境变量读取，否则随机生成
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,        # 禁止 JS 读取 cookie
    SESSION_COOKIE_SAMESITE="Lax",       # 防 CSRF（宽松模式）
    SESSION_COOKIE_NAME="user_session",  # 不叫默认的 session，增加安全性
    PERMANENT_SESSION_LIFETIME=1800,     # 30 分钟过期
)

# ============================================================
# 数据库初始化
# ============================================================

DB_PATH = "data/users.db"


def get_db():
    """获取数据库连接"""
    os.makedirs("data", exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
    # 插入默认用户（如果不存在）
    admin_pwd = generate_password_hash("admin123")
    alice_pwd = generate_password_hash("alice2025")
    for user in [
        ("admin", admin_pwd, "admin@example.com", "13800138000"),
        ("alice", alice_pwd, "alice@example.com", "13900139001"),
    ]:
        c.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
            user,
        )
    conn.commit()
    conn.close()


# ============================================================
# 辅助函数
# ============================================================

def get_user_from_db(username):
    """安全地从数据库获取用户信息"""
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "SELECT username, password, email, phone FROM users WHERE username = ?",
        (username,),
    )
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "username": row[0],
            "password": row[1],
            "email": row[2],
            "phone": row[3],
        }
    return None


def sanitize_text(text, max_len=100):
    """清洗输入文本"""
    if not text or not isinstance(text, str):
        return ""
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len]
    return text


def validate_username(username):
    """校验用户名：字母数字下划线中文，2-20位"""
    if not username or len(username) < 2 or len(username) > 20:
        return False
    return bool(re.match(r'^[a-zA-Z0-9_一-龥]{2,20}$', username))


def validate_password(password):
    """校验密码：至少8位"""
    return bool(password and len(password) >= 8)


def validate_email(email):
    """校验邮箱格式"""
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))


def validate_phone(phone):
    """校验手机号（中国大陆）"""
    return bool(re.match(r'^1[3-9]\d{9}$', phone))


# ============================================================
# 限流装饰器（防暴力破解）
# ============================================================

login_attempts = {}  # 内存记录，生产环境应放 Redis


def rate_limit(f):
    """同一个 IP 5 秒内只能尝试登录 3 次"""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        now = time.time()
        # 清理过期记录
        for addr in list(login_attempts.keys()):
            if now - login_attempts[addr]["time"] > 5:
                del login_attempts[addr]
        # 检查是否超限
        if ip in login_attempts and login_attempts[ip]["count"] >= 3:
            return render_template("login.html", error="登录尝试过于频繁，请5秒后再试")
        result = f(*args, **kwargs)
        # 只有失败才计数
        if isinstance(result, tuple) and result[1] == 429:
            if ip not in login_attempts:
                login_attempts[ip] = {"count": 0, "time": now}
            login_attempts[ip]["count"] += 1
            login_attempts[ip]["time"] = now
        return result
    return decorated


# ============================================================
# 登录装饰器
# ============================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ============================================================
# 路由：首页
# ============================================================

@app.route("/")
def index():
    user_id = session.get("user_id")
    username = session.get("username")
    user_info = None
    if user_id and username:
        user_info = get_user_from_db(username)
    return render_template("index.html", user=user_info)


# ============================================================
# 路由：登录（含限流）
# ============================================================

@app.route("/login", methods=["GET", "POST"])
@rate_limit
def login():
    if request.method == "POST":
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空")

        user = get_user_from_db(username)

        # 使用固定时间的比较，防止时序攻击
        if user and check_password_hash(user["password"], password):
            # 登录成功后重新生成 session（防 session 固定）
            session.clear()
            session.permanent = True
            session["user_id"] = user["username"]
            session["username"] = user["username"]
            # 密码不传到前端
            user_display = {k: v for k, v in user.items() if k != "password"}
            return render_template("index.html", user=user_display)
        else:
            # 统一的错误提示（防用户名枚举）
            return render_template("login.html", error="用户名或密码错误"), 429

    return render_template("login.html")


# ============================================================
# 路由：登出
# ============================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ============================================================
# 路由：注册
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")
        email = sanitize_text(request.form.get("email", ""))
        phone = sanitize_text(request.form.get("phone", ""))

        # ---- 服务端输入校验 ----
        errors = []
        if not validate_username(username):
            errors.append("用户名格式不正确（2-20位字母数字或中文）")
        if not validate_password(password):
            errors.append("密码至少需要8位")
        if not validate_email(email):
            errors.append("邮箱格式不正确")
        if not validate_phone(phone):
            errors.append("手机号格式不正确（11位手机号）")

        if errors:
            return render_template("register.html", error="；".join(errors))

        # 检查用户名是否已存在
        existing = get_user_from_db(username)
        if existing:
            return render_template("register.html", error="用户名已被注册")

        # ---- 写入数据库 ----
        hashed_pwd = generate_password_hash(password)
        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, hashed_pwd, email, phone),
            )
            conn.commit()
            return render_template("login.html", message="注册成功，请登录")
        except Exception:
            return render_template("register.html", error="注册失败，请稍后重试")
        finally:
            conn.close()

    return render_template("register.html")


# ============================================================
# 路由：搜索（仅登录用户可用）
# ============================================================

@app.route("/search")
@login_required
def search():
    keyword = sanitize_text(request.args.get("keyword", ""), 50)
    results = []

    if keyword:
        conn = get_db()
        c = conn.cursor()
        try:
            like_param = f"%{keyword}%"
            c.execute(
                "SELECT id, username, email, phone FROM users "
                "WHERE username LIKE ? OR email LIKE ?",
                (like_param, like_param),
            )
            results = c.fetchall()
        except Exception:
            pass
        finally:
            conn.close()

    username = session.get("username")
    user_info = get_user_from_db(username) if username else None
    return render_template("index.html", user=user_info, results=results, keyword=keyword)


# ============================================================
# 启动
# ============================================================

if __name__ == "__main__":
    init_db()
    # 生产环境不要用 debug 模式
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
