import sqlite3
import os
import re
import uuid
import secrets
import hmac
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# CSRF 保护配置
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_ENABLED=False,  # 不用 Flask-WTF，自制简单方案
)


# ============================================================
# CSRF 保护（基于 Session Token）
# ============================================================



def generate_csrf_token():
    """生成 CSRF Token 并存入 session"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token(token):
    """验证 CSRF Token"""
    stored = session.get("csrf_token")
    if not stored or not token:
        return False
    return hmac.compare_digest(stored, token)


def csrf_required(f):
    """CSRF 校验装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not validate_csrf_token(token):
                return render_template("login.html", error="请求已过期，请重试")
        return f(*args, **kwargs)
    return decorated


# 将 generate_csrf_token 注入模板上下文
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token())

# ============================================================
# 文件上传配置
# ============================================================

UPLOAD_FOLDER = Path("data/uploads")
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB


def allowed_file(filename):
    """白名单校验：只允许指定扩展名"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def verify_image_content(filepath):
    """验证文件内容是否为真实图片（检查魔数/Magic Bytes）"""
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        # PNG: 89 50 4E 47
        if header[:4] == b"\x89PNG":
            return True
        # JPEG: FF D8 FF
        if header[:2] == b"\xff\xd8" and header[3] == b"\xff"[0]:
            return True
        # GIF87a: 47 49 46 38 37 61
        if header[:6] in (b"GIF87a", b"GIF89a"):
            return True
        return False
    except Exception:
        return False


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
        phone TEXT,
        balance REAL DEFAULT 0
    )""")
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except Exception:
        pass
    admin_pwd = generate_password_hash("admin123")
    alice_pwd = generate_password_hash("alice2025")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", admin_pwd, "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", alice_pwd, "alice@example.com", "13900139001", 100))
    # 上传记录表
    c.execute("""CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        username TEXT NOT NULL,
        file_size INTEGER DEFAULT 0,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )""")
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


def get_user_by_id(user_id):
    """根据ID从数据库获取用户信息（含余额）"""
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    try:
        c.execute("SELECT id, username, email, phone, balance FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if row:
            return {"id": row[0], "username": row[1], "email": row[2], "phone": row[3], "balance": row[4]}
        return None
    except Exception:
        return None
    finally:
        conn.close()


# ============================================================
# 登录校验装饰器
# ============================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ============================================================
# 路由：首页
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        user_info = get_user_from_db(username)
    return render_template("index.html", user=user_info)


@app.route("/login", methods=["GET", "POST"])
@csrf_required
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
@csrf_required
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


# ============================================================
# 路由：个人中心（已修复——从session获取身份）
# ============================================================

@app.route("/profile")
@login_required
def profile():
    username = session.get("username")
    user_info = None
    if username:
        user_info = get_user_from_db(username)
        if user_info:
            # 获取带余额的完整信息
            user_id = user_info.get("id")
            # 用username从数据库查带余额的完整信息
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            c.execute("SELECT id, username, email, phone, balance FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            conn.close()
            if row:
                user_info = {"id": row[0], "username": row[1], "email": row[2], "phone": row[3], "balance": row[4]}
    return render_template("profile.html", user=user_info)


# ============================================================
# 路由：充值（已修复——从session获取身份 + 金额校验）
# ============================================================

@app.route("/recharge", methods=["POST"])
@login_required
@csrf_required
def recharge():
    username = session.get("username")
    if not username:
        return redirect("/login")

    amount_str = request.form.get("amount", "0")

    # 金额校验：必须为正数
    try:
        amount = float(amount_str)
        if amount <= 0:
            return render_template("profile.html", user=None, error="充值金额必须大于0")
        if amount > 100000:
            return render_template("profile.html", user=None, error="单次充值金额不能超过10万")
    except ValueError:
        return render_template("profile.html", user=None, error="金额格式不正确")

    # 只能给自己充值（从 session 获取用户名，不信任表单）
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET balance = balance + ? WHERE username = ?", (amount, username))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

    return redirect("/profile")


# ============================================================
# 路由：修改密码（无需验证原密码，无需验证身份）
# ============================================================

@app.route("/change-password", methods=["POST"])
@login_required
@csrf_required
def change_password():
    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not new_password or not confirm_password:
        return render_template("profile.html", error="请填写所有字段")

    if new_password != confirm_password:
        return render_template("profile.html", error="两次密码不一致")

    # 直接更新密码，不做任何校验
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET password = ? WHERE username = ?",
                  (generate_password_hash(new_password), username))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

    return redirect("/profile")


# ============================================================
# 路由：动态页面加载（已修复——白名单校验）
# ============================================================

ALLOWED_PAGES = {"help", "about", "contact", "faq"}

@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    error = None

    if name:
        # 清理输入：只保留文件名，去掉路径分隔符和..
        clean_name = os.path.basename(name)
        # 去掉扩展名
        if "." in clean_name:
            clean_name = clean_name.rsplit(".", 1)[0]

        # 白名单校验：只允许预定义页面
        if clean_name in ALLOWED_PAGES:
            file_path = os.path.join("pages", clean_name + ".html")
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                error = "页面不存在"
        else:
            error = "页面不存在"

    username = session.get("username")
    user_info = None
    if username:
        user_info = get_user_from_db(username)
    return render_template("index.html", user=user_info, page_content=page_content, page_error=error)


# ============================================================
# 路由：安全文件上传
# ============================================================

@app.route("/upload", methods=["GET", "POST"])
@login_required
@csrf_required
def upload_file():
    if request.method == "POST":
        # 检查是否有文件
        if "file" not in request.files:
            return render_template("upload.html", error="请选择文件")

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="请选择文件")

        # 1. 扩展名白名单校验
        if not allowed_file(file.filename):
            return render_template(
                "upload.html",
                error=f"不允许的文件类型，仅支持 {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            )

        # 2. 文件名安全检查
        original_name = secure_filename(file.filename)

        # 3. 生成随机文件名（防路径穿越、防文件名猜测）
        ext = original_name.rsplit(".", 1)[1].lower()
        new_filename = f"{uuid.uuid4().hex}.{ext}"
        save_path = UPLOAD_FOLDER / new_filename

        # 4. 保存到安全目录（不在 web 根目录下）
        file.save(save_path)

        # 5. 检查文件大小
        file_size = save_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            save_path.unlink()  # 删除超限文件
            return render_template("upload.html", error="文件大小超过限制（最大2MB）")

        # 6. 内容校验：验证魔数（Magic Bytes）
        if not verify_image_content(save_path):
            save_path.unlink()  # 删除伪造文件
            return render_template(
                "upload.html",
                error="文件内容不是有效的图片格式（仅接受真实 jpg/png/gif）",
            )

        # 7. 记录上传信息到数据库
        username = session["username"]
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO uploads (filename, original_name, username, file_size) VALUES (?, ?, ?, ?)",
                (new_filename, original_name, username, file_size),
            )
            conn.commit()
        except Exception:
            pass
        finally:
            conn.close()

        return render_template(
            "upload.html",
            success="文件上传成功！",
            filename=new_filename,
            original_name=original_name,
        )

    return render_template("upload.html")


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    """安全地提供上传的文件（通过 Flask 路由，不走静态目录）"""
    from flask import send_from_directory
    return send_from_directory(UPLOAD_FOLDER, filename)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
