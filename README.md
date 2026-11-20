# קולמוס · תמלול סיכומי שיעור בכתב יד עברי

מעלים תמונות או PDF של דפים בכתב יד (או מצלמים ישירות מהממשק), ומקבלים טקסט מוקלד שאפשר לערוך, להעתיק ולהוריד.
הזיהוי נעשה עם מודל ראייה, Gemini או Claude, דף-דף במקביל, והטקסט מוצג תוך כדי כתיבה. מילים שהמודל לא בטוח בהן מסומנות בצהוב.

## מנועי זיהוי

| מנוע | מפתח | הערות |
|---|---|---|
| **Gemini** | `GEMINI_API_KEY` מ-[Google AI Studio](https://aistudio.google.com/apikey) | יש שכבה חינמית עם מגבלת בקשות לדקה וליום. בשכבה החינמית Google עשויה להשתמש בתוכן לשיפור המוצרים שלה. |
| **Claude** | `ANTHROPIC_API_KEY` מ-[Anthropic Console](https://console.anthropic.com) | בתשלום לפי שימוש. |

מספיק להגדיר מפתח אחד. אם מוגדרים שניהם, מופיע בממשק בורר מנוע, וכך אפשר להשוות ביניהם על אותם דפים.

## הרצה בדוקר

```bash
cp .env.example .env        # ממלאים ANTHROPIC_API_KEY, APP_USERNAME, APP_PASSWORD, SECRET_KEY
docker compose up -d --build
```

הממשק זמין בכתובת http://localhost:8000

## הרצה מקומית בלי דוקר

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\uvicorn app:app --port 8000
```

## הערות

- **מצלמה בתוך הדף** דורשת HTTPS (או localhost). בטלפון בלי HTTPS הכפתור פותח את המצלמה של המכשיר, וזה עובד באותה צורה.
  בשרת מומלץ לשים מולו reverse proxy עם HTTPS (Caddy, nginx או Cloudflare Tunnel) ולהגדיר `COOKIE_SECURE=true`.
- כל שינוי של `APP_PASSWORD` מנתק את כל מי שמחובר.
- `CLAUDE_EFFORT` (low / medium / high / xhigh / max) מאזן בין דיוק למהירות ועלות. ברירת המחדל `high`.
