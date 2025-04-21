# main.py
import datetime
import json
import logging
import os
from contextlib import asynccontextmanager

import asyncpg
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from fastapi import FastAPI, Request, Form, Depends, status
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from phe import paillier
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.security import generate_password_hash, check_password_hash

from encryption import generate_homomorphic_keypair, deserialize_private_key, serialize_private_key

# --- Конфиг подключения к Postgres на Beget ---
DB_CONFIG = {
    "host": "quumdrafueyun.beget.app",
    "port": 5432,
    "user": "cloud_user",
    "password": "eLT1ApRZ%Fkf",
    "database": "default_db"
}


# --- Lifespan: пул соединений на стартап и шутдаун ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # при старте создаём пул
    app.state.db_pool = await asyncpg.create_pool(**DB_CONFIG)
    yield
    # при завершении закрываем
    await app.state.db_pool.close()


# --- Настройки FastAPI ---
app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key="secret_key_for_session")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")


# --- Зависимость для получения соединения ---
async def get_conn():
    async with app.state.db_pool.acquire() as conn:
        yield conn


# --- Зависимость для получения соединения ---
async def get_conn():
    async with app.state.db_pool.acquire() as conn:
        yield conn


# --- Главная страница ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, conn=Depends(get_conn)):
    polls = await conn.fetch("SELECT id, title, end_date FROM poll ORDER BY id DESC")
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
    # 0) Доступ и валидации
    if not request.session.get("is_admin"):
        return HTMLResponse("Доступ запрещен", status_code=403)
    if len(options) < 2:
        return HTMLResponse("Ошибка: как минимум два варианта", status_code=400)

    # 1) Генерируем гомоморфный ключ Paillier
    public_key, private_key = generate_homomorphic_keypair()

    # 2) Сохраняем публичные параметры в БД
    rec = await conn.fetchrow(
        '''
        INSERT INTO poll (title, end_date, public_key_n, public_key_g)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        ''',
        title,
        end_date,
        str(public_key.n),
        str(public_key.g),
    )
    poll_id = rec["id"]

    # 3) Кладём приватный ключ в защищённый каталог (не в БД!)
    priv_path = f"/var/secure/keys/poll_{poll_id}.key"
    os.makedirs(os.path.dirname(priv_path), exist_ok=True)
    with open(priv_path, "w", encoding="utf-8") as f:
        f.write(serialize_private_key(private_key))
    os.chmod(priv_path, 0o600)  # только для пользователя‑сервиса

    # 4) Добавляем варианты ответа
    for opt in options:
        await conn.execute(
            "INSERT INTO poll_options (poll_id, option_text) VALUES ($1, $2)",
            poll_id,
            opt,
        )

    # 5) Готово
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


def load_private_key(poll_id: int, public_key):
    """Читает приватный ключ Paillier для указанного опроса из защищённого каталога."""
    key_path = f"/var/secure/keys/poll_{poll_id}.key"
    with open(key_path, "r", encoding="utf-8") as f:
        return deserialize_private_key(f.read(), public_key)


# --- Голосование ---
@app.get("/poll/{poll_id}", response_class=HTMLResponse)
async def vote_get(
        request: Request,
        poll_id: int,
        conn=Depends(get_conn)
):
    # 0) Требуем авторизацию
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # 1) Достаём публичные данные опроса
    poll = await conn.fetchrow(
        "SELECT title, public_key_n, end_date FROM poll WHERE id = $1",
        poll_id
    )
    if not poll:
        return HTMLResponse("Голосование не найдено", status_code=404)

    title = poll["title"]
    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = load_private_key(poll_id, public_key)  # <- Читаем из /var/secure/keys
    end_date = poll["end_date"]

    # 2) Варианты ответов
    options = await conn.fetch(
        "SELECT id, option_text FROM poll_options WHERE poll_id = $1 ORDER BY id",
        poll_id
    )

    # 3) Открыто ли голосование?
    now = datetime.datetime.now().isoformat()
    is_closed = now >= end_date

    # 4) Ищем предыдущий голос пользователя (нужно для pre‑selection в форме)
    prev = await conn.fetchrow(
        "SELECT ciphertexts FROM vote WHERE poll_id = $1 AND user_id = $2",
        poll_id,
        user_id,
    )
    previous_vote = None
    if prev:
        arr = json.loads(prev["ciphertexts"])
        for (opt_id, _), cstr in zip(options, arr):
            if private_key.decrypt(paillier.EncryptedNumber(public_key, int(cstr))) == 1:
                previous_vote = opt_id
                break

    # 5) Текст всплывающего уведомления после POST‑редиректа
    voted_id = request.query_params.get("voted")
    voted_text = None
    if voted_id:
        for opt_id, opt_text in options:
            if str(opt_id) == voted_id:
                voted_text = opt_text
                break

    # 6) Рендерим шаблон
    return templates.TemplateResponse(
        "vote.html",
        {
            "request": request,
            "title": title,
            "poll_id": poll_id,
            "options": options,
            "previous_vote": previous_vote,
            "is_closed": is_closed,
            "can_change": not is_closed,
            "voted_text": voted_text,
        },
    )


@app.post("/poll/{poll_id}")
async def vote_post(
        request: Request,
        poll_id: int,
        selected_option: int = Form(..., alias="option"),
        priv_key_pem: str = Form(..., alias="priv_key"),
        conn=Depends(get_conn)
):
    # --- Авторизация ---
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # 1) Проверяем, что голосование ещё открыто
    poll = await conn.fetchrow(
        "SELECT public_key_n, end_date FROM poll WHERE id=$1",
        poll_id,
    )
    if not poll:
        return HTMLResponse("Голосование не найдено.", status_code=404)

    if datetime.datetime.now().isoformat() >= poll["end_date"]:
        return HTMLResponse("Голосование завершено.", status_code=400)

    # 2) Варианты
    options = await conn.fetch(
        "SELECT id FROM poll_options WHERE poll_id=$1 ORDER BY id",
        poll_id,
    )

    # 3) Формируем вектор шифротекстов
    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    ciphertexts = [
        str(public_key.encrypt(1 if opt["id"] == selected_option else 0).ciphertext())
        for opt in options
    ]

    # 4) Подписываем сообщение и проверяем приватный ключ
    msg = f"poll:{poll_id};user:{user_id};choices:{','.join(ciphertexts)}"
    h = SHA256.new(msg.encode())

    try:
        priv = RSA.import_key(priv_key_pem)  # ← приватный ключ пользователя
    except (ValueError, IndexError, TypeError):
        return HTMLResponse("Неверный формат приватного ключа.", status_code=400)

    # --- НОВАЯ проверка соответствия приватного ⇄ публичного ---
    stored_pub_pem = await conn.fetchval(
        'SELECT rsa_public_key FROM "user" WHERE id=$1',
        user_id,
    )
    if not stored_pub_pem:
        return HTMLResponse("В вашем профиле отсутствует публичный ключ.", status_code=400)

    try:
        stored_pub = RSA.import_key(stored_pub_pem)
    except (ValueError, IndexError, TypeError):
        return HTMLResponse("Сохранённый публичный ключ повреждён.", status_code=500)

    # Сравниваем параметры n и e
    if priv.n != stored_pub.n or priv.e != stored_pub.e:
        # --- НОВАЯ проверка соответствия приватного ⇄ публичного ---
        stored_pub_pem = await conn.fetchval(
            'SELECT rsa_public_key FROM "user" WHERE id=$1', user_id)

        # ↓↓↓   вставьте отладку  ↓↓↓

        logging.warning(
            "DEBUG‑RSA user=%s\npriv.n=%s\npriv.e=%s\npub .n=%s\npub .e=%s",
            user_id, hex(priv.n)[:80], priv.e, hex(RSA.import_key(stored_pub_pem).n)[:80],
            RSA.import_key(stored_pub_pem).e,
        )
        # ↑↑↑   конец отладки  ↑↑↑

        return HTMLResponse(
            "Приватный ключ не соответствует вашему публичному ключу.",
            status_code=400,
        )

    # 4‑б) Создаём подпись
    signature = pkcs1_15.new(priv).sign(h).hex()

    data = json.dumps(ciphertexts)

    # 5) Сохраняем или обновляем голос
    prev = await conn.fetchrow(
        "SELECT id FROM vote WHERE poll_id=$1 AND user_id=$2",
        poll_id,
        user_id,
    )
    if prev:
        await conn.execute(
            "UPDATE vote SET ciphertexts=$1, signature=$2 WHERE id=$3",
            data,
            signature,
            prev["id"],
        )
    else:
        await conn.execute(
            """
            INSERT INTO vote (poll_id, user_id, ciphertexts, signature)
            VALUES ($1, $2, $3, $4)
            """,
            poll_id,
            user_id,
            data,
            signature,
        )

    # 6) Успешный редирект
    return RedirectResponse(
        url=f"/poll/{poll_id}?voted={selected_option}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# --- Результаты ---
@app.get("/poll/{poll_id}/results", response_class=HTMLResponse)
async def poll_results(request: Request, poll_id: int, conn=Depends(get_conn)):
    """
    Подсчитываем итоги голосования гомоморфно и
    учитываем только голоса, подпись которых корректна.
    """
    # 1) Получаем публичный ключ опроса
    poll = await conn.fetchrow(
        "SELECT public_key_n FROM poll WHERE id=$1",
        poll_id,
    )
    if not poll:
        return HTMLResponse("Голосование не найдено", status_code=404)

    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = load_private_key(poll_id, public_key)  # /var/secure/keys/…

    # 2) Варианты ответа
    options = await conn.fetch(
        "SELECT id, option_text FROM poll_options WHERE poll_id=$1 ORDER BY id",
        poll_id,
    )

    # 3) Инициализируем сумму для каждого варианта (шифрование нуля)
    totals = [public_key.encrypt(0) for _ in options]

    # 4) Считываем все голоса вместе с подписью
    rows = await conn.fetch(
        "SELECT user_id, ciphertexts, signature FROM vote WHERE poll_id=$1",
        poll_id,
    )

    for row in rows:
        ct_list = json.loads(row["ciphertexts"])

        # --- Проверяем подпись бюллетеня ---
        msg = f"poll:{poll_id};user:{row['user_id']};choices:{','.join(ct_list)}"
        h = SHA256.new(msg.encode())
        user_pub_pem = await conn.fetchval(
            'SELECT rsa_public_key FROM "user" WHERE id=$1',
            row["user_id"],
        )
        try:
            pkcs1_15.new(RSA.import_key(user_pub_pem)).verify(
                h,
                bytes.fromhex(row["signature"]),
            )
        except (ValueError, TypeError):
            # Подпись не совпала → игнорируем голос
            continue

        # 5) Гомоморфное сложение компонент
        for i, cstr in enumerate(ct_list):
            totals[i] = totals[i] + paillier.EncryptedNumber(public_key, int(cstr))

    # 6) Расшифровка сумм → окончательные результаты
    results = {
        opt["option_text"]: private_key.decrypt(total)
        for opt, total in zip(options, totals)
    }

    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "results": results,
            "poll_id": poll_id,
        },
    )


@app.get("/poll/{poll_id}/verify", response_class=HTMLResponse)
async def verify_vote_get(
        request: Request,
        poll_id: int,
        conn=Depends(get_conn)  # ← нужно подключение
):
    # требуем авторизацию
    if not request.session.get("user_id"):
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # берём название опроса
    poll = await conn.fetchrow(
        "SELECT title FROM poll WHERE id=$1",
        poll_id,
    )
    if not poll:
        return HTMLResponse("Опрос не найден.", status_code=404)

    return templates.TemplateResponse(
        "verify_vote.html",
        {
            "request": request,
            "poll_id": poll_id,
            "title": poll["title"],  # ← передаём в шаблон
        },
    )


# --- Проверка голоса ---
@app.post("/poll/{poll_id}/verify", response_class=HTMLResponse)
async def verify_vote_post(
        request: Request,
        poll_id: int,
        priv_key_pem: str = Form(..., alias="priv_key"),
        conn=Depends(get_conn)
):
    import logging
    log = logging.getLogger("uvicorn.error")

    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # Проверяем соответствие приватного и публичного ключа
    try:
        priv = RSA.import_key(priv_key_pem)
    except (ValueError, IndexError, TypeError):
        return HTMLResponse("Неверный формат приватного ключа.", status_code=400)

    stored_pub_pem = await conn.fetchval(
        'SELECT rsa_public_key FROM "user" WHERE id=$1', user_id
    )
    try:
        stored_pub = RSA.import_key(stored_pub_pem)
    except (ValueError, IndexError, TypeError):
        return HTMLResponse("Сохранённый публичный ключ повреждён.", status_code=500)

    if priv.n != stored_pub.n or priv.e != stored_pub.e:
        log.warning(
            "VERIFY‑RSA mismatch user=%s\npriv.n=%s\npriv.e=%s\npub .n=%s\npub .e=%s",
            user_id, hex(priv.n)[:80], priv.e, hex(stored_pub.n)[:80], stored_pub.e,
        )
        return HTMLResponse(
            "Приватный ключ не соответствует вашему публичному ключу.",
            status_code=400,
        )

    # Достаём зашифрованный бюллетень и подпись пользователя
    row = await conn.fetchrow(
        "SELECT ciphertexts, signature FROM vote WHERE poll_id=$1 AND user_id=$2",
        poll_id,
        user_id,
    )
    if not row:
        return HTMLResponse("Ваш голос не найден.", status_code=404)

    ct_list = json.loads(row["ciphertexts"])
    msg = f"poll:{poll_id};user:{user_id};choices:{','.join(ct_list)}"
    h = SHA256.new(msg.encode())
    try:
        pkcs1_15.new(stored_pub).verify(h, bytes.fromhex(row["signature"]))
    except (ValueError, TypeError):
        return HTMLResponse(
            "Ошибка: подпись вашего голоса не прошла проверку.",
            status_code=400,
        )

    # Получаем название опроса + Paillier ключ
    poll = await conn.fetchrow(
        "SELECT title, public_key_n FROM poll WHERE id=$1",
        poll_id,
    )
    if not poll:
        return HTMLResponse("Опрос не найден.", status_code=404)
    title = poll["title"]
    public_key = paillier.PaillierPublicKey(n=int(poll["public_key_n"]))
    private_key = load_private_key(poll_id, public_key)

    # Расшифровка
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

    option = await conn.fetchrow(
        """
        SELECT option_text
        FROM   poll_options
        WHERE  poll_id=$1
        ORDER  BY id
        OFFSET $2
        LIMIT  1
        """,
        poll_id,
        chosen_opt_id,
    )

    return templates.TemplateResponse(
        "verify_vote.html",
        {
            "request": request,
            "poll_id": poll_id,
            "title": title,  # ← теперь передаётся в шаблон
            "chosen": option["option_text"],
        },
    )


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
