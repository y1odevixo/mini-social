#!/usr/bin/env python3
# Мини-соцсеть: регистрация по email + пароль, профиль, посты, личные сообщения.
# Запуск:
#   pip install flask
#   python mini_social_auth.py
# Открой: http://127.0.0.1:5000

from flask import Flask, request, redirect, session, abort, jsonify
import sqlite3
import time
import re
import os
from pathlib import Path
from html import escape
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_ME_TO_SOMETHING_RANDOM")  # поменяй для продакшена
DB_PATH = Path("mini_social_auth.db")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------- DB ----------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        bio TEXT DEFAULT '',
        created_at INTEGER NOT NULL
      )
    """)
    cur.execute("""
      CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(author_id) REFERENCES users(id)
      )
    """)
    cur.execute("""
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
      )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- helpers ----------------
def now_ts():
    return int(time.time())

def fmt_time(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = db()
    u = conn.execute("SELECT id, email, display_name, bio FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return u

def page(title, body, user=None):
    user = user or current_user()
    nav = ""
    if user:
        nav = f"""
        <div class="top">
          <div>
            <span class="pill">Вы: <b>{escape(user["display_name"])}</b></span>
            <span class="muted">({escape(user["email"])})</span>
          </div>
          <div class="links">
            <a href="/">Лента</a>
            <a href="/people">Люди</a>
            <a href="/inbox">Входящие</a>
            <a href="/profile">Профиль</a>
            <a href="/logout">Выход</a>
          </div>
        </div>
        """
    else:
        nav = """
        <div class="top">
          <div class="muted">Вы не вошли</div>
          <div class="links">
            <a href="/login">Вход</a>
            <a href="/register">Регистрация</a>
          </div>
        </div>
        """

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{escape(title)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; max-width: 980px; margin: 24px auto; padding: 0 14px; background:#fafafa; }}
    .top {{ display:flex; gap:12px; align-items:center; justify-content:space-between; flex-wrap:wrap; margin-bottom: 12px; }}
    .links {{ display:flex; gap:12px; flex-wrap:wrap; }}
    .card {{ border:1px solid #e5e7eb; border-radius:14px; padding:14px; margin: 12px 0; background:#fff; }}
    textarea, input {{ width:100%; box-sizing:border-box; padding:10px; border:1px solid #e5e7eb; border-radius:12px; }}
    button {{ padding:10px 14px; border-radius:12px; border:1px solid #e5e7eb; background:#f3f4f6; cursor:pointer; }}
    button:hover {{ background:#e5e7eb; }}
    a {{ color:#0b57d0; text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
    .muted {{ color:#6b7280; font-size: 13px; }}
    .pill {{ display:inline-block; padding:6px 10px; border:1px solid #e5e7eb; border-radius:999px; background:#fff; }}
    .row {{ display:flex; gap:10px; flex-wrap:wrap; }}
    .row > * {{ flex:1; min-width: 220px; }}
    .msg-me {{ background:#eef6ff; }}
    .error {{ color:#b91c1c; }}
  </style>
</head>
<body>
  {nav}
  {body}
</body>
</html>"""

def sanitize_display_name(name: str) -> str:
    name = (name or "").strip()
    name = re.sub(r"\s+", " ", name)
    name = name[:24]
    return name or "User"
@app.get("/api/dm")
@login_required
def api_dm():
    user = current_user()
    me = user["id"]

    peer = int(request.args.get("to", "0"))
    after = int(request.args.get("after", "0"))

    conn = db()

    rows = conn.execute("""
        SELECT id, sender_id, receiver_id, text, created_at
        FROM messages
        WHERE id > ?
        AND (
            (sender_id=? AND receiver_id=?)
            OR
            (sender_id=? AND receiver_id=?)
        )
        ORDER BY id ASC
    """, (after, me, peer, peer, me)).fetchall()

    conn.close()

    return jsonify([
        {
            "id": r["id"],
            "sender_id": r["sender_id"],
            "text": r["text"],
            "created_at": r["created_at"]
        }
        for r in rows
    ])
# ---------------- auth ----------------
@app.get("/register")
def register_page():
    body = """
    <div class="card">
      <h2>Регистрация</h2>
      <form method="post" action="/register">
        <label class="muted">Email</label>
        <input name="email" type="email" placeholder="you@example.com" required/>
        <label class="muted" style="margin-top:10px; display:block;">Пароль (минимум 6 символов)</label>
        <input name="password" type="password" required/>
        <label class="muted" style="margin-top:10px; display:block;">Имя/ник (как будет видно другим)</label>
        <input name="display_name" placeholder="Например: Alex" required/>
        <div style="margin-top:10px;">
          <button type="submit">Создать аккаунт</button>
        </div>
      </form>
      <p class="muted">Пока без подтверждения по почте — чтобы запускалось сразу.</p>
    </div>
    """
    return page("Регистрация", body, user=None)

@app.post("/register")
def register():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    display_name = sanitize_display_name(request.form.get("display_name") or "")

    if not EMAIL_RE.match(email):
        return page("Регистрация", f'<div class="card error">Некорректный email</div>', None), 400
    if len(password) < 6:
        return page("Регистрация", f'<div class="card error">Пароль слишком короткий</div>', None), 400

    pw_hash = generate_password_hash(password)

    conn = db()
    try:
        conn.execute(
            "INSERT INTO users(email, password_hash, display_name, bio, created_at) VALUES(?,?,?,?,?)",
            (email, pw_hash, display_name, "", now_ts())
        )
        conn.commit()
        user_id = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    except sqlite3.IntegrityError:
        conn.close()
        return page("Регистрация", '<div class="card error">Этот email уже зарегистрирован</div>', None), 400
    conn.close()

    session["user_id"] = user_id
    return redirect("/")

@app.get("/login")
def login_page():
    body = """
    <div class="card">
      <h2>Вход</h2>
      <form method="post" action="/login">
        <label class="muted">Email</label>
        <input name="email" type="email" placeholder="you@example.com" required/>
        <label class="muted" style="margin-top:10px; display:block;">Пароль</label>
        <input name="password" type="password" required/>
        <div style="margin-top:10px;">
          <button type="submit">Войти</button>
        </div>
      </form>
    </div>
    """
    return page("Вход", body, user=None)

@app.post("/login")
def login():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    conn = db()
    u = conn.execute("SELECT id, password_hash FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if not u or not check_password_hash(u["password_hash"], password):
        return page("Вход", '<div class="card error">Неверный email или пароль</div>', None), 400

    session["user_id"] = u["id"]
    return redirect("/")

@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------- main features ----------------
@app.get("/")
@login_required
def feed():
    user = current_user()

    conn = db()
    posts = conn.execute("""
      SELECT p.id, p.content, p.created_at, u.display_name, u.id AS author_id
      FROM posts p
      JOIN users u ON u.id = p.author_id
      ORDER BY p.id DESC
      LIMIT 50
    """).fetchall()
    conn.close()

    items = []
    for p in posts:
        items.append(f"""
          <div class="card">
            <div class="muted">
              <b>{escape(p["display_name"])}</b> • {escape(fmt_time(p["created_at"]))}
              — <a href="/dm?to={p["author_id"]}">написать</a>
            </div>
            <div style="white-space:pre-wrap; margin-top:8px;">{escape(p["content"])}</div>
          </div>
        """)

    body = f"""
    <div class="card">
      <h2>Лента</h2>
      <form method="post" action="/post">
        <label class="muted">Новый пост:</label>
        <textarea name="content" rows="3" placeholder="Напиши что-нибудь..." required></textarea>
        <div style="margin-top:10px;">
          <button type="submit">Опубликовать</button>
        </div>
      </form>
    </div>
    {''.join(items) if items else '<div class="card muted">Пока нет постов. Напиши первый 🙂</div>'}
    """
    return page("Лента", body, user=user)

@app.post("/post")
@login_required
def add_post():
    user = current_user()
    content = (request.form.get("content") or "").strip()
    if not content:
        return redirect("/")
    content = content[:2000]

    conn = db()
    conn.execute("INSERT INTO posts(author_id, content, created_at) VALUES(?,?,?)",
                 (user["id"], content, now_ts()))
    conn.commit()
    conn.close()
    return redirect("/")

@app.get("/people")
@login_required
def people():
    user = current_user()
    conn = db()
    users = conn.execute("""
      SELECT id, display_name, email, bio
      FROM users
      ORDER BY id DESC
      LIMIT 200
    """).fetchall()
    conn.close()

    cards = []
    for u in users:
        cards.append(f"""
          <div class="card">
            <div><b>{escape(u["display_name"])}</b> <span class="muted">({escape(u["email"])})</span></div>
            <div class="muted" style="margin-top:6px; white-space:pre-wrap;">{escape(u["bio"] or "")}</div>
            <div style="margin-top:8px;">
              <a href="/dm?to={u["id"]}">Написать</a>
            </div>
          </div>
        """)

    body = f"""
    <div class="card">
      <h2>Люди</h2>
      <p class="muted">Все зарегистрированные пользователи.</p>
    </div>
    {''.join(cards)}
    """
    return page("Люди", body, user=user)

@app.get("/profile")
@login_required
def profile():
    user = current_user()
    body = f"""
    <div class="card">
      <h2>Профиль</h2>
      <form method="post" action="/profile">
        <label class="muted">Имя/ник</label>
        <input name="display_name" value="{escape(user["display_name"])}" maxlength="24" required/>
        <label class="muted" style="margin-top:10px; display:block;">О себе</label>
        <textarea name="bio" rows="4" maxlength="500" placeholder="Коротко о себе...">{escape(user["bio"] or "")}</textarea>
        <div style="margin-top:10px;">
          <button type="submit">Сохранить</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h3>Смена пароля</h3>
      <form method="post" action="/profile/password">
        <label class="muted">Текущий пароль</label>
        <input name="old_password" type="password" required/>
        <label class="muted" style="margin-top:10px; display:block;">Новый пароль (мин 6)</label>
        <input name="new_password" type="password" required/>
        <div style="margin-top:10px;">
          <button type="submit">Поменять пароль</button>
        </div>
      </form>
    </div>
    """
    return page("Профиль", body, user=user)

@app.post("/profile")
@login_required
def profile_save():
    user = current_user()
    display_name = sanitize_display_name(request.form.get("display_name") or "")
    bio = (request.form.get("bio") or "").strip()[:500]

    conn = db()
    conn.execute("UPDATE users SET display_name=?, bio=? WHERE id=?",
                 (display_name, bio, user["id"]))
    conn.commit()
    conn.close()
    return redirect("/profile")

@app.post("/profile/password")
@login_required
def profile_password():
    user = current_user()
    old_pw = request.form.get("old_password") or ""
    new_pw = request.form.get("new_password") or ""

    if len(new_pw) < 6:
        return page("Профиль", '<div class="card error">Новый пароль слишком короткий</div>', user), 400

    conn = db()
    u = conn.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
    if not u or not check_password_hash(u["password_hash"], old_pw):
        conn.close()
        return page("Профиль", '<div class="card error">Текущий пароль неверный</div>', user), 400

    conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                 (generate_password_hash(new_pw), user["id"]))
    conn.commit()
    conn.close()
    return redirect("/profile")

@app.get("/dm")
@login_required
def dm():
    user = current_user()
    try:
        other_id = int(request.args.get("to") or "0")
    except ValueError:
        return redirect("/people")
    if other_id <= 0:
        return redirect("/people")

    conn = db()
    other = conn.execute("SELECT id, display_name, email FROM users WHERE id=?", (other_id,)).fetchone()
    if not other:
        conn.close()
        return redirect("/people")

    msgs = conn.execute("""
      SELECT m.sender_id, m.receiver_id, m.text, m.created_at, su.display_name AS sname, ru.display_name AS rname
      FROM messages m
      JOIN users su ON su.id = m.sender_id
      JOIN users ru ON ru.id = m.receiver_id
      WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
      ORDER BY m.id DESC
      LIMIT 100
    """, (user["id"], other_id, other_id, user["id"])).fetchall()
    conn.close()
    msgs = list(reversed(msgs))

    bubbles = []
    for m in msgs:
        mine = (m["sender_id"] == user["id"])
        cls = "card msg-me" if mine else "card"
        bubbles.append(f"""
          <div class="{cls}">
            <div class="muted">
              {escape(m["sname"])} → {escape(m["rname"])} • {escape(fmt_time(m["created_at"]))}
            </div>
            <div style="white-space:pre-wrap; margin-top:8px;">{escape(m["text"])}</div>
          </div>
        """)

    body = f"""
    <div class="card">
      <h2>Диалог с {escape(other["display_name"])} <span class="muted">({escape(other["email"])})</span></h2>
      <form method="post" action="/dm/send">
        <input type="hidden" name="to" value="{other_id}"/>
        <label class="muted">Сообщение</label>
        <textarea name="text" rows="3" maxlength="2000" placeholder="Напиши сообщение..." required></textarea>
        <div style="margin-top:10px;">
          <button type="submit">Отправить</button>
        </div>
      </form>
    </div>
    <div id="chat-box">
{''.join(bubbles) if bubbles else '<div class="card muted">Сообщений пока нет.</div>'}
</div>
    <script>
<script>
<script>
const params = new URLSearchParams(window.location.search);
const peerId = params.get("to");

let lastId = 0;

async function checkMessages() {{
  try {{
    const res = await fetch("/api/dm?to=" + peerId + "&after=" + lastId);
    const data = await res.json();

    if (data.length > 0) {{
      const box = document.getElementById("chat-box");

      data.forEach(msg => {{
        lastId = Math.max(lastId, msg.id);

        const div = document.createElement("div");
        div.className = "card";
        div.textContent = msg.text;
        box.appendChild(div);
      }});

      box.scrollTop = box.scrollHeight;
    }}
  }} catch (e) {{}}

  setTimeout(checkMessages, 1200);
}}

checkMessages();
</script>
"""
    return page("Личные сообщения", body, user=user)

@app.post("/dm/send")
@login_required
def dm_send():
    user = current_user()
    try:
        other_id = int(request.form.get("to") or "0")
    except ValueError:
        return redirect("/people")
    text = (request.form.get("text") or "").strip()
    if other_id <= 0 or not text:
        return redirect("/people")

    text = text[:2000]

    conn = db()
    other = conn.execute("SELECT id FROM users WHERE id=?", (other_id,)).fetchone()
    if not other:
        conn.close()
        return redirect("/people")

    conn.execute(
        "INSERT INTO messages(sender_id, receiver_id, text, created_at) VALUES(?,?,?,?)",
        (user["id"], other_id, text, now_ts())
    )
    conn.commit()
    conn.close()
    return redirect(f"/dm?to={other_id}")

@app.get("/inbox")
@login_required
def inbox():
    user = current_user()
    conn = db()
    # список диалогов по последнему сообщению
    rows = conn.execute("""
      SELECT
        CASE WHEN sender_id=? THEN receiver_id ELSE sender_id END AS peer_id,
        MAX(id) AS last_msg_id
      FROM messages
      WHERE sender_id=? OR receiver_id=?
      GROUP BY peer_id
      ORDER BY last_msg_id DESC
      LIMIT 100
    """, (user["id"], user["id"], user["id"])).fetchall()

    cards = []
    for r in rows:
        peer_id = r["peer_id"]
        peer = conn.execute("SELECT id, display_name, email FROM users WHERE id=?", (peer_id,)).fetchone()
        last = conn.execute("SELECT text, created_at FROM messages WHERE id=?", (r["last_msg_id"],)).fetchone()
        if not peer or not last:
            continue
        preview = last["text"]
        if len(preview) > 120:
            preview = preview[:120] + "…"
        cards.append(f"""
          <div class="card">
            <div><b>{escape(peer["display_name"])}</b> <span class="muted">({escape(peer["email"])}) • {escape(fmt_time(last["created_at"]))}</span></div>
            <div class="muted" style="margin-top:6px; white-space:pre-wrap;">{escape(preview)}</div>
            <div style="margin-top:8px;"><a href="/dm?to={peer_id}">Открыть диалог</a></div>
          </div>
        """)

    conn.close()
    body = f"""
    <div class="card">
      <h2>Входящие / Диалоги</h2>
      <p class="muted">Последние активные диалоги.</p>
    </div>
    {''.join(cards) if cards else '<div class="card muted">Диалогов пока нет.</div>'}
    """
    return page("Входящие", body, user=user)

# ---------------- run ----------------
if __name__ == "__main__":
    # Для общения с друзьями в одной сети можно поставить host="0.0.0.0"
    # и открыть порт 5000 на роутере/фаерволе.
    app.run(host="0.0.0.0", port=5000, debug=True)














