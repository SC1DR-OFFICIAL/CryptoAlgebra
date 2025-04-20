# main.py
import datetime

import asyncpg
from fastapi import FastAPI, Request, Form, Depends, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from phe import paillier
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import generate_password_hash, check_password_hash

from encryption import generate_homomorphic_keypair, serialize_private_key, deserialize_private_key

from Crypto.PublicKey    import RSA
from Crypto.Signature    import pkcs1_15
from Crypto.Hash         import SHA256


# --- Настройки FastAPI ---
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="secret_key_for_session")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- Конфиг подключения к Postgres на Beget ---
DB_CONFIG = {
    "host": "quumdrafueyun.beget.app",
    "port": 5432,
    "user": "cloud_user",
    "password": "eLT1ApRZ%Fkf",
    "database": "default_db"
}


# --- Стартап и шутдаун: создаём пул соединений ---
@app.on_event("startup")
async def startup():
    app.state.db_pool = await asyncpg.create_pool(**DB_CONFIG)


@app.on_event("shutdown")
async def shutdown():
    await app.state.db_pool.close()


# --- Зависимость для получения соединения ---
async def get_conn():
    async with app.state.db_pool.acquire() as conn:
        yield conn


# --- Главная страница ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, conn=Depends(get_conn)):
    polls = await conn.fetch("SELECT id, title, end_date FROM poll ORDER BY id")
    now = datetime.datetime.now().isoformat()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "polls": polls,
        "now": now
    })


# --- Регистрация ---
@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        conn=Depends(get_conn)
):
    # 1) Хешируем пароль
    password_hash = generate_password_hash(password)

    # 2) Генерируем RSA‑ключи
    rsa_key = RSA.generate(2048)
    private_pem = rsa_key.export_key().decode()
    public_pem = rsa_key.publickey().export_key().decode()

    # 3) Сохраняем в сессии приватный ключ, в БД — публичный
    request.session["rsa_private_key"] = private_pem
    await conn.execute(
        'INSERT INTO "user" (username, password_hash, rsa_public_key) VALUES ($1, $2, $3)',
        username, password_hash, public_pem
    )
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


# --- Вход ---
@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        conn=Depends(get_conn)
):
    row = await conn.fetchrow(
        'SELECT id, password_hash, is_admin FROM "user" WHERE username = $1',
        username
    )
    if row and check_password_hash(row["password_hash"], password):
        request.session["user_id"] = row["id"]
        request.session["username"] = username
        request.session["is_admin"] = row["is_admin"]
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Неверный логин или пароль"
    })


# --- Страница про гомоморфизм ---
@app.get("/homomorphic-info", response_class=HTMLResponse)
async def homomorphic_info(request: Request):
    return templates.TemplateResponse("homomorphic_info.html", {"request": request})


# --- Создание голосования (админ) ---
@app.get("/admin/create_poll", response_class=HTMLResponse)
async def create_poll_get(request: Request):
    if not request.session.get("is_admin"):
        return HTMLResponse("Доступ запрещен", status_code=403)
    return templates.TemplateResponse("create_poll.html", {"request": request})


@app.post("/admin/create_poll")
async def create_poll_post(
        request: Request,
        title: str = Form(...),
        end_date: str = Form(...),
        options: list[str] = Form(...),
        conn=Depends(get_conn)
):
    if not request.session.get("is_admin"):
        return HTMLResponse("Доступ запрещен", status_code=403)
    if len(options) < 2:
        return HTMLResponse("Ошибка: как минимум два варианта", status_code=400)

    public_key, private_key = generate_homomorphic_keypair()
    rec = await conn.fetchrow('''
        INSERT INTO poll (title, end_date, public_key_n, public_key_g, private_key)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
    ''',
                              title, end_date,
                              str(public_key.n), str(public_key.g),
                              serialize_private_key(private_key)
                              )
    poll_id = rec["id"]

    # Вставляем варианты
    for opt in options:
        await conn.execute(
            "INSERT INTO poll_options (poll_id, option_text) VALUES ($1, $2)",
            poll_id, opt
        )

    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


# --- Голосование ---
@app.get("/poll/{poll_id}", response_class=HTMLResponse)
async def vote_get(request: Request, poll_id: int, conn=Depends(get_conn)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    poll = await conn.fetchrow(
        "SELECT title, public_key_n, end_date FROM poll WHERE id = $1",
        poll_id
    )
    options = await conn.fetch(
        "SELECT id, option_text FROM poll_options WHERE poll_id = $1 ORDER BY id",
        poll_id
    )
    if not poll or not options:
        return HTMLResponse("Голосование не найдено", status_code=404)

    now = datetime.datetime.now().isoformat()
    is_closed = now >= poll["end_date"]
    prev = await conn.fetchrow(
        "SELECT option_id FROM vote WHERE poll_id=$1 AND user_id=$2",
        poll_id, user_id
    )

    return templates.TemplateResponse("vote.html", {
        "request": request,
        "title": poll["title"],
        "poll_id": poll_id,
        "options": options,
        "previous_vote": prev and prev["option_id"],
        "is_closed": is_closed
    })


@app.post("/poll/{poll_id}")
async def vote_post(
        request: Request,
        poll_id: int,
        option: int = Form(..., alias="option"),
        conn=Depends(get_conn)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    poll = await conn.fetchrow(
        "SELECT public_key_n, end_date FROM poll WHERE id = $1",
        poll_id
    )
    now = datetime.datetime.now().isoformat()
    if now >= poll["end_date"]:
        return HTMLResponse("Голосование завершено.", status_code=400)

    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    encrypted = public_key.encrypt(1).ciphertext()

    # --- Формируем сообщение и подписываем его приватным ключом из сессии ---
    msg = f"poll:{poll_id};user:{user_id};option:{option}"
    h = SHA256.new(msg.encode())
    priv = RSA.import_key(request.session["rsa_private_key"])
    signature = pkcs1_15.new(priv).sign(h).hex()

    prev = await conn.fetchrow(
        "SELECT id FROM vote WHERE poll_id=$1 AND user_id=$2",
        poll_id, user_id
    )

    if prev:
        await conn.execute(
            "UPDATE vote SET option_id=$1, encrypted_vote=$2, signature=$3 WHERE id=$4",
            option, str(encrypted), signature, prev["id"]
        )
    else:
        await conn.execute(
            "INSERT INTO vote (poll_id, user_id, option_id, encrypted_vote, signature) VALUES ($1,$2,$3,$4,$5)",
            poll_id, user_id, option, str(encrypted), signature
        )

    return RedirectResponse(url=f"/poll/{poll_id}", status_code=status.HTTP_303_SEE_OTHER)


# --- Результаты ---
@app.get("/poll/{poll_id}/results", response_class=HTMLResponse)
async def poll_results(request: Request, poll_id: int, conn=Depends(get_conn)):
    poll = await conn.fetchrow(
        "SELECT public_key_n, private_key FROM poll WHERE id = $1",
        poll_id
    )
    if not poll:
        return HTMLResponse("Голосование не найдено", status_code=404)

    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = deserialize_private_key(poll["private_key"], public_key)

    options = await conn.fetch(
        "SELECT id, option_text FROM poll_options WHERE poll_id=$1 ORDER BY id",
        poll_id
    )
    results: dict[str, int] = {}

    # Сначала верифицируем подписи и отбираем валидные
    for opt in options:
        rows = await conn.fetch("SELECT user_id, encrypted_vote, signature FROM vote WHERE poll_id=$1 AND option_id=$2",
                                poll_id, opt["id"])
        valid_enc = []
        for row in rows:
            msg = f"poll:{poll_id};user:{row['user_id']};option:{opt['id']}"
            h = SHA256.new(msg.encode())
            # получаем публичный ключ голосующего
            user_pub = await conn.fetchval('SELECT rsa_public_key FROM "user" WHERE id=$1', row["user_id"])
            try:
                pkcs1_15.new(RSA.import_key(user_pub)).verify(h, bytes.fromhex(row["signature"]))
                # подпись верна — учитываем голос
                valid_enc.append(paillier.EncryptedNumber(public_key, int(row["encrypted_vote"])))
            except (ValueError, TypeError):
                # подпись неверна — пропускаем
                continue

        if valid_enc:
            total = sum(valid_enc)
            results[opt["option_text"]] = private_key.decrypt(total)
        else:
            results[opt["option_text"]] = 0

    return templates.TemplateResponse("results.html", {
        "request": request,
        "results": results
    })


# --- Удаление опроса (админ) ---
@app.post("/admin/poll/{poll_id}/delete")
async def delete_poll(request: Request, poll_id: int, conn=Depends(get_conn)):
    if not request.session.get("is_admin"):
        return HTMLResponse("Доступ запрещен", status_code=403)

    await conn.execute("DELETE FROM vote WHERE poll_id = $1", poll_id)
    await conn.execute("DELETE FROM poll_options WHERE poll_id = $1", poll_id)
    await conn.execute("DELETE FROM poll WHERE id = $1", poll_id)

    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


# --- Выход ---
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
