# SQL 注入漏洞修复报告

---

## 一、概述

### 1.1 项目信息

| 项目 | 内容 |
|------|------|
| 项目名称 | 用户信息管理平台 |
| 开发框架 | Python Flask |
| 数据库 | SQLite |
| 修复日期 | 2026-07-08 |

### 1.2 什么是 SQL 注入？——用大白话解释

SQL 注入就像**在银行填单子时夹带私货**。

正常情况：你在取款单上写"取 100 元"，柜员照办。

SQL 注入：你在取款单上写"取 100 元，顺便把保险柜里所有钱转给我"。如果柜员（数据库）没有检查你的单子，就真的执行了。

**换到网站的场景：**

用户注册时，在"用户名"这一栏输入的不是正常名字，而是一段 SQL 代码。网站直接把这段代码拼接到 SQL 语句中执行，结果就悲剧了。

---

## 二、发现的问题

### 2.1 问题 1：注册功能存在 SQL 注入（高危）

**漏洞代码：**
```python
# ❌ 错误写法：直接把用户输入拼接到 SQL 里
sql = f"INSERT INTO users (username, password, email, phone) 
        VALUES ('{username}', '{password}', '{email}', '{phone}')"
c.execute(sql)
```

**问题在哪？** 假如用户在用户名输入：
```
hacker'), ('admin', 'newpass', 'hack@x.com', '123')-- 
```

拼接后就变成了：
```sql
INSERT INTO users (username, password, email, phone) 
VALUES ('hacker'), ('admin', 'newpass', 'hack@x.com', '123')--', '...', '...', '...')
```

**后果：** 攻击者可以：
- 注册任意账号
- 覆盖已有账号密码
- 删除整个用户表
- 读取数据库里的所有数据

**危害等级：⭐⭐⭐⭐⭐（严重）**

### 2.2 问题 2：搜索功能存在 SQL 注入（高危）

**漏洞代码：**
```python
# ❌ 错误写法：直接把搜索关键词拼接到 SQL 里
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
c.execute(sql)
```

**问题在哪？** 假设用户在搜索框输入：
```
' OR '1'='1
```

拼接后就变成了：
```sql
SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' OR email LIKE '%' OR '1'='1%'
```

`'1'='1'` 永远为真，所以**一次搜索就把全库用户信息全拉出来了**。

更危险的是，攻击者还可以这样搜：
```
' UNION SELECT 1,username,password FROM users--
```

直接**窃取所有人的用户名和密码**。

**危害等级：⭐⭐⭐⭐⭐（严重）**

### 2.3 问题 3：密码明文存储（高危）

**漏洞代码：**
```python
USERS = {
    "admin": { "password": "admin123", ... },  # ❌ 明文！
    "alice": { "password": "alice2025", ... }  # ❌ 明文！
}
```

更糟糕的是，**登录后的页面直接展示了用户的密码**：
```html
<!-- index.html 中直接显示密码 -->
<tr><td>密码</td><td>{{ user.password }}</td></tr>
```

**问题在哪？** 一旦数据库泄露，所有用户的密码就全部曝光。而现实中很多人**所有网站都用同一个密码**，攻击者拿到后可以去其他网站碰运气。

**危害等级：⭐⭐⭐⭐（高危）**

### 2.4 问题 4：密钥写死在代码里（中危）

**漏洞代码：**
```python
app.secret_key = "dev-key-2025"  # ❌ 固定的密钥！
```

**问题在哪？** Flask 用这个密钥加密用户的登录状态（session）。如果密钥是固定的 `dev-key-2025`，攻击者可以伪造任意用户的登录状态，直接以管理员身份登录。

**危害等级：⭐⭐⭐（中危）**

### 2.5 问题 5：调试注释泄露密码（低危）

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

**问题在哪？** 任何人都可以查看网页源代码，直接看到管理员的账号密码。

**危害等级：⭐⭐（低危）**

---

## 三、修复方案

### 3.1 修复 1：参数化查询——防 SQL 注入的"疫苗"

**核心思想：** 把 SQL 语句和数据分开，就像**填空**而不是**造句**。

**之前：** "把用户说的话直接接到 SQL 句子里" → 用户可以说任何话
**之后：** "SQL 语句先设计好，用户填的数据只当数据用" → 用户无法篡改 SQL

```python
# ✅ 正确写法：使用 ? 占位符，数据单独传入
c.execute(
    "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
    (username, password, email, phone)  # 数据单独传，不会被当成SQL执行
)
```

```python
# ✅ 搜索也改成参数化
like_param = f"%{keyword}%"
c.execute(
    "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?",
    (like_param, like_param)
)
```

**参数化查询的原理：**

```
用户输入:  ' OR '1'='1

❌ 拼接方式： WHERE username LIKE '%' OR '1'='1%'
              ↑ 变成了SQL语法的一部分

✅ 参数化方式： WHERE username LIKE ?
                传入: "%' OR '1'='1%"
                ↑ 被当成纯文本匹配，不是SQL语法
```

### 3.2 修复 2：密码哈希存储

**核心思想：** 不存密码本身，存密码的"指纹"。

```
密码 "admin123"  
    ↓ 经过哈希算法
"pbkdf2:sha256:260000$abcdefg$hijklmnopqrstuvwxyz1234567890"
    ↑ 这串乱码存到数据库
```

**特点：**
- 从这串乱码**无法反推出**原始密码
- 用户登录时，把输入的密码用同样算法算一遍，比对两串乱码是否相同
- 即使数据库泄露，攻击者也拿不到原始密码

```python
from werkzeug.security import generate_password_hash, check_password_hash

# 注册时：存哈希
hashed_password = generate_password_hash(password)
c.execute("INSERT INTO users ... VALUES (?)", (hashed_password,))

# 登录时：比对哈希
if check_password_hash(stored_hash, input_password):
    # 密码正确
```

### 3.3 修复 3：输入校验——设门槛

```python
# 增加基本的格式检查
if not re.match(r'^1[3-9]\d{9}$', phone):
    return "手机号格式不正确"
if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
    return "邮箱格式不正确"
if len(username) > 20:
    return "用户名过长"
```

### 3.4 修复 4：随机生成密钥

```python
# ✅ 每次部署都随机生成，无人能预测
app.secret_key = os.urandom(24).hex()
```

### 3.5 修复 5：删除调试信息和密码显示

- 删掉了 HTML 中的调试注释
- 密码不再显示在前端页面

---

## 四、修复前后对比

| 功能 | 修复前 | 修复后 |
|------|--------|--------|
| **注册** | 直接拼 SQL → **可注入** | 参数化查询 → **安全** |
| **搜索** | 直接拼 SQL → **可注入** | 参数化查询 → **安全** |
| **密码存储** | 明文 `admin123` | 哈希 `pbkdf2:sha256:...` |
| **登录验证** | 硬编码字典 | 数据库读取 + 哈希比对 |
| **密钥** | 固定 `dev-key-2025` | 随机生成 |
| **密码显示** | 页面上直接展示密码 | 隐藏为 `••••••••` |
| **输入校验** | 无 | 用户名/邮箱/手机号格式校验 |
| **调试信息** | HTML注释泄露账号密码 | 已删除 |

---

## 五、修复验证

### 5.1 注入测试结果

| 测试项 | 修复前 | 修复后 |
|-------|:-----:|:-----:|
| 搜索 `' OR '1'='1` | ✅ 返回全部用户 | ❌ 返回空 |
| 搜索 `' UNION SELECT ...` | ✅ 窃取数据 | ❌ 返回空 |
| 注册时注入 SQL | ✅ 执行成功 | ❌ 被拦截 |

### 5.2 正常功能测试结果

| 功能 | 结果 |
|-----|:---:|
| admin 登录 | ✅ 正常 |
| 新用户注册 | ✅ 正常 |
| 用户搜索 | ✅ 正常 |

---

## 六、安全建议总结

```
防止 SQL 注入的三个层次：

第一层（必须做）：参数化查询
  所有涉及数据库的查询，都用 ? 占位符，不要拼接字符串

第二层（必须做）：密码哈希
  永远不要存明文密码，用 bcrypt / pbkdf2 等标准算法

第三层（建议做）：输入校验
  对用户输入做格式检查，长度限制，特殊字符过滤
```

### 一句话记住

> **永远不要把用户的输入直接拼到 SQL 语句里。用参数化查询，就像用填空代替造句，简单又安全。**

---

*报告生成日期：2026-07-08*
*修复项目：用户信息管理平台（Python Flask + SQLite）*
*修复提交：[f91e630](https://github.com/Curry30ytx/-/commit/f91e630)*
