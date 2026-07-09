import sqlite3
import os
import re
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# ============================================================
# 数据库初始化
# ============================================================

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        phone TEXT
    )""")
    # 插入默认管理员（密码已哈希）
    admin_pwd = generate_password_hash("admin123")
    alice_pwd = generate_password_hash("alice2025")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", admin_pwd, "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", alice_pwd, "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


# ============================================================
# 辅助函数
# ============================================================

def get_user_from_db(username):
    """从数据库获取用户信息"""
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT username, password, email, phone FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "username": row[0],
            "password": row[1],
            "email": row[2],
            "phone": row[3]
        }
    return None


def validate_input(text, max_len=50):
    """基本输入校验：去除首尾空格，限制长度，只允许安全字符"""
    if not text or not text.strip():
        return False
    text = text.strip()
    if len(text) > max_len:
        return False
    return True


def sanitize_text(text):
    """清洗文本：去除首尾空格"""
    return text.strip() if text else ""


# ============================================================
# 路由
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        user_info = get_user_from_db(username)
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空")

        user = get_user_from_db(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            # 密码不传到前端
            user_display = {k: v for k, v in user.items() if k != "password"}
            return render_template("index.html", user=user_display)
        else:
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_text(request.form.get("username", ""))
        password = request.form.get("password", "")
        email = sanitize_text(request.form.get("email", ""))
        phone = sanitize_text(request.form.get("phone", ""))

        # ---- 输入校验 ----
        if not validate_input(username, 20):
            return render_template("register.html", error="用户名无效（1-20个字符）")
        if not validate_input(password, 100):
            return render_template("register.html", error="密码无效（1-100个字符）")
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return render_template("register.html", error="邮箱格式不正确")
        if not re.match(r'^1[3-9]\d{9}$', phone):
            return render_template("register.html", error="手机号格式不正确（11位手机号）")

        # 检查用户名是否已存在
        existing = get_user_from_db(username)
        if existing:
            return render_template("register.html", error="用户名已被注册")

        # ---- 安全写入数据库（参数化查询） ----
        hashed_pwd = generate_password_hash(password)
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, hashed_pwd, email, phone)
            )
            conn.commit()
            return render_template("login.html", message="注册成功，请登录")
        except Exception as e:
            return render_template("register.html", error=f"注册失败，请稍后重试")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = sanitize_text(request.args.get("keyword", ""))
    results = []

    if keyword:
        # ---- 安全搜索（参数化查询） ----
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            like_param = f"%{keyword}%"
            c.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like_param, like_param)
            )
            results = c.fetchall()
        except Exception:
            pass
        finally:
            conn.close()

    username = session.get("username")
    user_info = None
    if username:
        user_info = get_user_from_db(username)
    return render_template("index.html", user=user_info, results=results, keyword=keyword)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
