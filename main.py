# main.py
import datetime
import json

import asyncpg
from fastapi import FastAPI, Request, Form, Depends, status, Response, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from phe import paillier
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import generate_password_hash, check_password_hash

from encryption import generate_homomorphic_keypair, serialize_private_key, deserialize_private_key

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

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

    # 2) Генерируем пару RSA‑ключей
    rsa_key = RSA.generate(2048)
    private_pem = rsa_key.export_key().decode()
    public_pem = rsa_key.publickey().export_key().decode()

    # 3) Сохраняем пользователя с публичным ключом
    rec = await conn.fetchrow(
        'INSERT INTO "user" (username, password_hash, rsa_public_key) '
        'VALUES ($1, $2, $3) RETURNING id',
        username, password_hash, public_pem
    )

    # 4) Автоматически логиним и сохраняем приватный ключ в сессии
    request.session["user_id"] = rec["id"]
    request.session["username"] = username
    request.session["is_admin"] = False
    request.session["rsa_private_key"] = private_pem

    # 5) Перенаправляем на страницу показа ключа
    return RedirectResponse(url="/mykey", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/mykey", response_class=HTMLResponse)
async def show_my_key(request: Request):
    # Доступ только для залогиненных пользователей
    if not request.session.get("user_id"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    priv = request.session.get("rsa_private_key")
    return templates.TemplateResponse("show_key.html", {
        "request": request,
        "private_key": priv
    })


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
async def vote_get(
        request: Request,
        poll_id: int,
        conn=Depends(get_conn)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # Получаем данные опроса
    poll = await conn.fetchrow(
        "SELECT title, public_key_n, private_key, end_date FROM poll WHERE id = $1",
        poll_id
    )
    if not poll:
        return HTMLResponse("Голосование не найдено", status_code=404)

    title = poll["title"]
    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = deserialize_private_key(poll["private_key"], public_key)
    end_date = poll["end_date"]

    # Варианты ответов
    options = await conn.fetch(
        "SELECT id, option_text FROM poll_options WHERE poll_id = $1 ORDER BY id",
        poll_id
    )
    # Статус голосования
    now = datetime.datetime.now().isoformat()
    is_closed = now >= end_date

    # Старая запись — для pre‑selection
    prev = await conn.fetchrow(
        "SELECT ciphertexts FROM vote WHERE poll_id = $1 AND user_id = $2",
        poll_id, user_id
    )
    previous_vote = None
    if prev:
        # дешифруем вектор, находим единственный 1
        arr = json.loads(prev["ciphertexts"])
        for (opt_id, _), cstr in zip(options, arr):
            if private_key.decrypt(paillier.EncryptedNumber(public_key, int(cstr))) == 1:
                previous_vote = opt_id
                break

    # Параметр из POST‑редиректа ?voted=ID
    voted_id = request.query_params.get("voted")
    voted_text = None
    if voted_id:
        for opt_id, opt_text in options:
            if str(opt_id) == voted_id:
                voted_text = opt_text
                break

    # Отдаём **все** переменные, на которые ссылаются в templates/vote.html
    return templates.TemplateResponse("vote.html", {
        "request": request,
        "title": title,
        "poll_id": poll_id,
        "options": options,
        "previous_vote": previous_vote,
        "is_closed": is_closed,
        "can_change": not is_closed,
        "voted_text": voted_text
    })


@app.post("/poll/{poll_id}", response_class=HTMLResponse)
async def vote_post(
    request: Request,
    poll_id: int,
    selected_option: int = Form(..., alias="option"),
    priv_key_pem: str     = Form(..., alias="priv_key"),
    conn=Depends(get_conn)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=303)

    # Проверяем открытость голосования
    poll = await conn.fetchrow("SELECT public_key_n, end_date FROM poll WHERE id=$1", poll_id)
    now = datetime.datetime.now().isoformat()
    if now >= poll["end_date"]:
        return await _render_vote_page(request, poll_id, conn, "Голосование уже завершено.")

    # Импорт приватного ключа
    try:
        priv = RSA.import_key(priv_key_pem)
    except Exception:
        return await _render_vote_page(request, poll_id, conn, "Неверный формат приватного ключа.")

    # Сверяем ключи по n/e
    stored_pub_pem = await conn.fetchval('SELECT rsa_public_key FROM "user" WHERE id=$1', user_id)
    stored_pub     = RSA.import_key(stored_pub_pem)
    user_pub       = priv.publickey()
    if stored_pub.n != user_pub.n or stored_pub.e != user_pub.e:
        return await _render_vote_page(request, poll_id, conn, "Этот приватный ключ не соответствует вашему аккаунту.")

    # Всё ок, шифруем + подписываем + сохраняем
    options = await conn.fetch("SELECT id FROM poll_options WHERE poll_id=$1 ORDER BY id", poll_id)
    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    ciphertexts = [str(public_key.encrypt(1 if opt["id"]==selected_option else 0).ciphertext())
                   for opt in options]
    msg = f"poll:{poll_id};user:{user_id};choices:{','.join(ciphertexts)}"
    h   = SHA256.new(msg.encode())
    signature = pkcs1_15.new(priv).sign(h).hex()
    data = json.dumps(ciphertexts)

    prev = await conn.fetchrow("SELECT id FROM vote WHERE poll_id=$1 AND user_id=$2", poll_id, user_id)
    if prev:
        await conn.execute("UPDATE vote SET ciphertexts=$1, signature=$2 WHERE id=$3",
                           data, signature, prev["id"])
    else:
        await conn.execute(
          "INSERT INTO vote(poll_id,user_id,ciphertexts,signature) VALUES($1,$2,$3,$4)",
          poll_id, user_id, data, signature
        )

    # Редирект, чтобы показать Alert об успехе
    return RedirectResponse(f"/poll/{poll_id}?voted={selected_option}", status_code=303)


async def _render_vote_page(request: Request, poll_id: int, conn, error_message: str):
    """
    Общая функция для отображения страницы голосования с переданным сообщением об ошибке.
    """
    # Повторяем логику vote_get для контекста
    poll = await conn.fetchrow(
        "SELECT title, public_key_n, private_key, end_date FROM poll WHERE id = $1",
        poll_id
    )
    title       = poll["title"]
    public_key  = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = deserialize_private_key(poll["private_key"], public_key)
    end_date    = poll["end_date"]

    options = await conn.fetch(
        "SELECT id, option_text FROM poll_options WHERE poll_id = $1 ORDER BY id",
        poll_id
    )
    now       = datetime.datetime.now().isoformat()
    is_closed = now >= end_date

    prev = await conn.fetchrow(
        "SELECT ciphertexts FROM vote WHERE poll_id = $1 AND user_id = $2",
        poll_id, request.session.get("user_id")
    )
    previous_vote = None
    if prev:
        arr = json.loads(prev["ciphertexts"])
        for (opt_id, _), cstr in zip(options, arr):
            if private_key.decrypt(paillier.EncryptedNumber(public_key, int(cstr))) == 1:
                previous_vote = opt_id
                break

    return templates.TemplateResponse("vote.html", {
        "request": request,
        "title": title,
        "poll_id": poll_id,
        "options": options,
        "previous_vote": previous_vote,
        "is_closed": is_closed,
        "can_change": not is_closed,
        "voted_text": None,
        "error_message": error_message
    })


# --- Результаты ---
@app.get("/poll/{poll_id}/results", response_class=HTMLResponse)
async def poll_results(request: Request, poll_id: int, conn=Depends(get_conn)):
    # 1) Получаем ключи Паилье
    poll = await conn.fetchrow(
        "SELECT public_key_n, private_key FROM poll WHERE id=$1", poll_id
    )
    if not poll:
        return HTMLResponse("Голосование не найдено", status_code=404)

    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = deserialize_private_key(poll["private_key"], public_key)

    # 2) Получаем варианты
    options = await conn.fetch(
        "SELECT id, option_text FROM poll_options WHERE poll_id=$1 ORDER BY id", poll_id
    )

    # 3) Инициализируем суммы как зашифровку нуля
    totals = [public_key.encrypt(0) for _ in options]

    # 4) Считываем все зашифрованные векторы голосов
    rows = await conn.fetch(
        "SELECT user_id, ciphertexts, signature FROM vote WHERE poll_id=$1", poll_id
    )

    for row in rows:
        # (опционально) проверяем подпись row["signature"] здесь…

        ct_list = json.loads(row["ciphertexts"])
        # 5) Гомоморфно складываем по каждому индексу
        for i, cstr in enumerate(ct_list):
            totals[i] = totals[i] + paillier.EncryptedNumber(public_key, int(cstr))

    # 6) Расшифровываем каждую сумму
    results = {}
    for opt, total in zip(options, totals):
        count = private_key.decrypt(total)
        results[opt["option_text"]] = count

    return templates.TemplateResponse("results.html", {
        "request": request,
        "results": results,
        "poll_id": poll_id
    })


@app.get("/poll/{poll_id}/verify", response_class=HTMLResponse)
async def verify_vote_get(request: Request, poll_id: int):
    # убедимся, что пользователь залогинен
    if not request.session.get("user_id"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("verify_vote.html", {
        "request": request,
        "poll_id": poll_id
    })


@app.post("/poll/{poll_id}/verify", response_class=HTMLResponse)
async def verify_vote_post(
        request: Request,
        poll_id: int,
        priv_key_pem: str = Form(..., alias="priv_key"),
        conn=Depends(get_conn)
):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # 1) Достаём запись голосования этого пользователя
    row = await conn.fetchrow(
        "SELECT ciphertexts, signature FROM vote WHERE poll_id=$1 AND user_id=$2",
        poll_id, user_id
    )
    if not row:
        return HTMLResponse("Ваш голос не найден.", status_code=404)

    # 2) Верифицируем подпись
    ct_list = json.loads(row["ciphertexts"])
    msg = f"poll:{poll_id};user:{user_id};choices:{','.join(ct_list)}"
    h = SHA256.new(msg.encode())
    pub_pem = await conn.fetchval('SELECT rsa_public_key FROM "user" WHERE id=$1', user_id)
    try:
        pkcs1_15.new(RSA.import_key(pub_pem)).verify(h, bytes.fromhex(row["signature"]))
    except (ValueError, TypeError):
        return HTMLResponse("Ошибка: подпись вашего голоса не прошла проверку.", status_code=400)

    # 3) Дешифруем вектор и находим выбранный вариант
    poll = await conn.fetchrow("SELECT public_key_n, private_key FROM poll WHERE id=$1", poll_id)
    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = deserialize_private_key(poll["private_key"], public_key)

    chosen_opt_id = None
    for idx, cstr in enumerate(ct_list):
        val = private_key.decrypt(
            paillier.EncryptedNumber(public_key, int(cstr))
        )
        if val == 1:
            chosen_opt_id = idx
            break

    if chosen_opt_id is None:
        return HTMLResponse("Не удалось определить ваш выбор.", status_code=400)

    # 4) Получаем текст варианта
    option = await conn.fetchrow(
        "SELECT option_text FROM poll_options WHERE poll_id=$1 ORDER BY id OFFSET $2 LIMIT 1",
        poll_id, chosen_opt_id
    )

    return templates.TemplateResponse("verify_vote.html", {
        "request": request,
        "poll_id": poll_id,
        "chosen": option["option_text"]
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
