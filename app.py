"""Hebrew handwriting -> typed text.

FastAPI backend: receives page photos / scans / PDFs, prepares them, and streams a
faithful transcription from Claude's vision model back to the browser (SSE).
Access is protected by a single username/password taken from environment variables.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import time
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path

import anthropic
from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from PIL import Image, ImageOps, UnidentifiedImageError

try:  # iPhone photos (HEIC/HEIF)
    from pillow_heif import register_heif_opener

    register_heif_opener()
except ImportError:  # pragma: no cover
    pass

load_dotenv()

# ---------------------------------------------------------------- configuration
APP_USERNAME = os.environ.get("APP_USERNAME", "").strip()
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
if not APP_USERNAME or not APP_PASSWORD:
    raise RuntimeError("APP_USERNAME and APP_PASSWORD must be set (see .env.example)")

# Without a fixed SECRET_KEY every restart logs everybody out - still safe.
SECRET_KEY = (os.environ.get("SECRET_KEY") or secrets.token_hex(32)).encode()
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
SESSION_SECONDS = int(os.environ.get("SESSION_DAYS", "30")) * 86400
COOKIE_NAME = "hw_session"

MODEL = os.environ.get("CLAUDE_MODEL", "claude-opus-5-5")
EFFORT = os.environ.get("CLAUDE_EFFORT", "high")
MAX_CONCURRENCY = int(os.environ.get("MAX_CONCURRENCY", "4"))
MAX_FILES = int(os.environ.get("MAX_FILES", "40"))
MAX_FILE_BYTES = int(os.environ.get("MAX_FILE_MB", "30")) * 1024 * 1024

# Highest resolution the current vision models read natively.
MAX_EDGE = 2576
MAX_PIXELS = 3_750_000
MAX_IMAGE_BYTES = 4_500_000  # API limit is 5 MB per base64 image

STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------- prompt
SYSTEM_PROMPT = """You are an expert transcriber of handwritten Hebrew. You receive a photo or scan of handwritten lesson notes (a summary of a class, written by a student or teacher) and produce an exact typed transcription of it.

Accuracy is the only goal. The reader will rely on your text instead of the original page, so every word must be what the writer wrote.

1. Transcribe word for word, in reading order. Do not summarize, paraphrase, translate, complete unfinished sentences, add content, or fix the writer's grammar or style.
2. Read the whole page and work out the subject before committing to individual words. Hebrew handwriting often confuses letter pairs such as ר/ד, ו/ז/י/ן, ה/ח/ת, ב/כ, ס/ם, ע/צ, ג/נ, ט/מ - where a letter is ambiguous, choose the reading that forms a real word that fits the sentence and the topic.
3. Crossed-out text (struck through or scribbled over) was deleted by the writer: leave it out completely. Text inserted above the line or from the margin with a caret or arrow goes where it points. Other margin notes go right after the paragraph they sit beside, as: [הערה בשוליים: ...]
4. Keep the structure: titles and headings on their own line, paragraph breaks, numbered lists ("1.") and bullet lists ("-"), sub-points indented by two spaces per level. Join lines that the writer broke only because the paper ran out of width; keep line breaks that carry meaning.
5. Keep abbreviations exactly as written, with their marks (ע"י, וכו', ז"א, לדוג') - do not expand them. Keep English words, numbers, dates, formulas and symbols (→, =, ≠, ✓) as written; write equations in plain text.
6. A word you cannot read with confidence: write your best reading wrapped in ⟦ ⟧, for example ⟦מילה⟧. A completely illegible word: ⟦?⟧. Use these marks only where you are genuinely unsure, never as decoration.
7. Tables: one row per line, " | " between cells. Drawings and diagrams: a short description in square brackets, e.g. [איור: ציר זמן של המאה ה-19], then the handwritten labels from it.
8. Ignore printed notebook furniture (logos, printed headers, page-number boxes) unless something is handwritten in it.

Output only the transcription: no introduction, no closing remarks, no code fences, and no Markdown symbols (no #, no **)."""

IMAGE_INSTRUCTION = "תמלל את הדף."
PDF_INSTRUCTION = (
    "תמלל את כל העמודים במסמך לפי הסדר. בין עמוד לעמוד כתוב שורה נפרדת: — עמוד N —"
)


# ---------------------------------------------------------------- auth helpers
def _password_fingerprint() -> str:
    # Changing the password in .env invalidates every existing session.
    return hashlib.sha256(APP_PASSWORD.encode()).hexdigest()[:16]


def _sign(expires: int) -> str:
    msg = f"{expires}|{APP_USERNAME}|{_password_fingerprint()}".encode()
    return hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()


def make_session_token() -> str:
    expires = int(time.time()) + SESSION_SECONDS
    return f"{expires}.{_sign(expires)}"


def is_authenticated(request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME, "")
    expires_str, _, signature = token.partition(".")
    if not expires_str.isdigit() or not signature:
        return False
    expires = int(expires_str)
    if expires < time.time():
        return False
    return hmac.compare_digest(signature, _sign(expires))


def credentials_match(username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username.strip().encode(), APP_USERNAME.encode())
    pass_ok = hmac.compare_digest(password.encode(), APP_PASSWORD.encode())
    return user_ok and pass_ok


# Brute-force protection: at most 8 failed logins per IP per 15 minutes.
_FAILED_LOGINS: dict[str, deque[float]] = defaultdict(deque)
_FAIL_WINDOW = 15 * 60
_FAIL_LIMIT = 8


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _too_many_failures(ip: str) -> bool:
    attempts = _FAILED_LOGINS[ip]
    now = time.time()
    while attempts and attempts[0] < now - _FAIL_WINDOW:
        attempts.popleft()
    return len(attempts) >= _FAIL_LIMIT


# ---------------------------------------------------------------- image prep
def prepare_image(data: bytes) -> bytes:
    """Orient, resize to the model's native maximum, gently normalize contrast."""
    img = Image.open(io.BytesIO(data))
    img = ImageOps.exif_transpose(img)  # phone photos are often stored sideways
    img = img.convert("RGB")

    w, h = img.size
    scale = min(1.0, MAX_EDGE / max(w, h), (MAX_PIXELS / (w * h)) ** 0.5)
    if scale < 1.0:
        img = img.resize((max(1, round(w * scale)), max(1, round(h * scale))), Image.LANCZOS)

    # Faint pencil and grey shadows from phone cameras: stretch the tonal range a
    # little without changing ink colours. No binarization - it destroys strokes.
    img = ImageOps.autocontrast(img, cutoff=0.5, preserve_tone=True)

    for quality in (92, 85, 75, 65):
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=quality, optimize=True)
        if buf.tell() <= MAX_IMAGE_BYTES:
            return buf.getvalue()
    return buf.getvalue()


# ---------------------------------------------------------------- Claude
class TranscriptionError(Exception):
    pass


@lru_cache(maxsize=1)
def get_client() -> anthropic.AsyncAnthropic:
    return anthropic.AsyncAnthropic(max_retries=4)


async def transcribe_page(data: bytes):
    """Async generator yielding transcription text chunks for one file."""
    if data[:5] == b"%PDF-":
        block = {
            "type": "document",
            "source": {
                "type": "base64",
                "media_type": "application/pdf",
                "data": base64.standard_b64encode(data).decode(),
            },
        }
        instruction = PDF_INSTRUCTION
    else:
        try:
            jpeg = await asyncio.to_thread(prepare_image, data)
        except (UnidentifiedImageError, OSError) as exc:
            raise TranscriptionError("הקובץ אינו תמונה או PDF תקינים") from exc
        block = {
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/jpeg",
                "data": base64.standard_b64encode(jpeg).decode(),
            },
        }
        instruction = IMAGE_INSTRUCTION

    async with get_client().beta.messages.stream(
        model=MODEL,
        max_tokens=64000,
        thinking={"type": "adaptive"},
        output_config={"effort": EFFORT},
        # If a safety classifier declines, the API retries on a suitable model.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": [block, {"type": "text", "text": instruction}],
            }
        ],
    ) as stream:
        async for text in stream.text_stream:
            yield text
        final = await stream.get_final_message()

    if final.stop_reason == "refusal":
        raise TranscriptionError("המודל סירב לתמלל את הדף")
    if final.stop_reason == "max_tokens":
        yield "\n\n[התמלול נקטע - המסמך ארוך מדי. פצלו אותו לקבצים קטנים יותר]"


def friendly_error(exc: Exception) -> str:
    if isinstance(exc, TranscriptionError):
        return str(exc)
    if isinstance(exc, anthropic.AuthenticationError):
        return "מפתח ה-API של Anthropic חסר או שגוי (ANTHROPIC_API_KEY)"
    if isinstance(exc, anthropic.PermissionDeniedError):
        return "למפתח ה-API אין הרשאה למודל הזה"
    if isinstance(exc, anthropic.RateLimitError):
        return "עומס זמני על השירות - נסו שוב בעוד דקה"
    if isinstance(exc, anthropic.BadRequestError):
        return f"הבקשה נדחתה: {exc.message}"
    if isinstance(exc, anthropic.APIStatusError):
        return f"שגיאה בשירות התמלול ({exc.status_code}) - נסו שוב"
    if isinstance(exc, anthropic.APIConnectionError):
        return "אין חיבור לשירות התמלול"
    if isinstance(exc, anthropic.AnthropicError) and "auth" in str(exc).lower():
        return "מפתח ה-API של Anthropic חסר (ANTHROPIC_API_KEY)"
    return "שגיאה לא צפויה בתמלול"


# ---------------------------------------------------------------- app
app = FastAPI(title="Hebrew Handwriting", docs_url=None, redoc_url=None, openapi_url=None)

PUBLIC_API = {"/api/login", "/api/session"}


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in PUBLIC_API and not is_authenticated(request):
        return JSONResponse({"error": "נדרשת התחברות"}, status_code=401)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/api/session")
async def session(request: Request):
    return {"authenticated": is_authenticated(request)}


@app.post("/api/login")
async def login(request: Request):
    ip = _client_ip(request)
    if _too_many_failures(ip):
        return JSONResponse({"error": "יותר מדי ניסיונות. נסו שוב בעוד כמה דקות"}, status_code=429)
    try:
        body = await request.json()
        username, password = str(body.get("username", "")), str(body.get("password", ""))
    except Exception:
        raise HTTPException(400, "בקשה לא תקינה")

    if not credentials_match(username, password):
        _FAILED_LOGINS[ip].append(time.time())
        await asyncio.sleep(0.6)  # slow down guessing
        return JSONResponse({"error": "שם משתמש או סיסמה שגויים"}, status_code=401)

    _FAILED_LOGINS.pop(ip, None)
    response = JSONResponse({"ok": True})
    response.set_cookie(
        COOKIE_NAME,
        make_session_token(),
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )
    return response


@app.post("/api/logout")
async def logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME)
    return response


@app.post("/api/transcribe")
async def transcribe(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(400, "לא נבחרו קבצים")
    if len(files) > MAX_FILES:
        raise HTTPException(400, f"אפשר להעלות עד {MAX_FILES} קבצים בכל פעם")

    pages: list[bytes] = []
    for f in files:
        data = await f.read()
        if not data:
            raise HTTPException(400, f"הקובץ {f.filename} ריק")
        if len(data) > MAX_FILE_BYTES:
            raise HTTPException(413, f"הקובץ {f.filename} גדול מדי")
        pages.append(data)

    async def events():
        queue: asyncio.Queue = asyncio.Queue()
        limiter = asyncio.Semaphore(MAX_CONCURRENCY)

        async def work(index: int, data: bytes):
            async with limiter:
                await queue.put({"type": "page_start", "page": index})
                try:
                    async for chunk in transcribe_page(data):
                        await queue.put({"type": "delta", "page": index, "text": chunk})
                    await queue.put({"type": "page_done", "page": index})
                except Exception as exc:  # report per page, keep the others going
                    await queue.put(
                        {"type": "page_error", "page": index, "message": friendly_error(exc)}
                    )

        tasks = [asyncio.create_task(work(i, d)) for i, d in enumerate(pages)]

        async def finish():
            await asyncio.gather(*tasks, return_exceptions=True)
            await queue.put(None)

        finisher = asyncio.create_task(finish())
        try:
            yield ": start\n\n"
            while (item := await queue.get()) is not None:
                yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
            yield 'data: {"type": "done"}\n\n'
        finally:  # client went away -> stop paying for the remaining pages
            for t in tasks:
                t.cancel()
            finisher.cancel()

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
