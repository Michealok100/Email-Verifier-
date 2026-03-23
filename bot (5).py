"""
Telegram Bot interface for the Email Verification Tool.

Commands:
  /start        — welcome message
  /verify <email> — verify a single email
  /upload       — prompt user to upload a CSV file
  /help         — usage instructions

Upload a CSV file directly in the chat to bulk-verify.
The bot will reply with a results CSV.

Setup:
  1. Create a bot via @BotFather and get your token
  2. Set TELEGRAM_BOT_TOKEN in config.py (or as env var)
  3. pip install -r requirements.txt
  4. python bot.py
"""

import csv
import io
import logging
import os
import tempfile
import time
from pathlib import Path

from telegram import Update, Document
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from config import LOG_FILE, LOG_LEVEL
from verifier import verify_email, Status, OUTPUT_FIELDS

# ── Config ────────────────────────────────────────────────────────────────────
# Set via environment variable or paste token directly here as fallback
TELEGRAM_BOT_TOKEN: str = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")

# Max emails per CSV upload (protect against abuse)
MAX_EMAILS_PER_UPLOAD: int = 500

# ── Logging ───────────────────────────────────────────────────────────────────
def _setup_logging() -> None:
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    fmt   = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
    logging.basicConfig(
        level=level, format=fmt,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
        ],
    )

logger = logging.getLogger("bot")

# ── Status emoji map ─────────────────────────────────────────────────────────
STATUS_EMOJI = {
    Status.VALID:          "✅",
    Status.INVALID:        "❌",
    Status.RISKY:          "⚠️",
    Status.UNKNOWN:        "❓",
    Status.DOMAIN_INVALID: "🚫",
}

# ── Handlers ──────────────────────────────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "👋 *Email Verification Bot*\n\n"
        "I verify email addresses for bounce reduction.\n\n"
        "*Commands:*\n"
        "`/verify user@example.com` — check a single email\n"
        "`/help` — show status explanations\n\n"
        "📎 *Bulk:* Upload a CSV file with an `email` column "
        "and I'll return a results CSV.",
        parse_mode="Markdown",
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "📖 *Status guide:*\n\n"
        "✅ *VALID* — Mailbox confirmed (high confidence)\n"
        "❌ *INVALID* — Mailbox/domain rejected (high confidence)\n"
        "⚠️ *RISKY* — Catch-all domain; result uncertain\n"
        "❓ *UNKNOWN* — Server blocked probe; don't assume invalid\n"
        "🚫 *DOMAIN\\_INVALID* — Domain has no DNS/MX records\n\n"
        "⚠️ *Limitations:*\n"
        "• Gmail, Outlook, Yahoo block SMTP probing → UNKNOWN\n"
        "• Catch-all domains (many corporate) → RISKY\n"
        "• Results are probabilistic, not guaranteed\n"
        "• Accuracy improves with a reputable sending IP",
        parse_mode="Markdown",
    )


async def cmd_verify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /verify <email>"""
    if not context.args:
        await update.message.reply_text(
            "Usage: `/verify user@example.com`", parse_mode="Markdown"
        )
        return

    email = context.args[0].strip()
    msg   = await update.message.reply_text(f"🔍 Verifying `{email}`…", parse_mode="Markdown")

    try:
        result = verify_email(email)
        emoji  = STATUS_EMOJI.get(result.status, "❓")
        text   = (
            f"{emoji} *{result.status.value}* ({result.confidence.value})\n"
            f"📧 `{result.email}`\n"
        )
        if result.mx_server_used:
            text += f"🖥 MX: `{result.mx_server_used}`\n"
        if result.notes:
            text += f"📝 {result.notes}"

        await msg.edit_text(text, parse_mode="Markdown")

    except Exception as exc:
        logger.error("Error verifying %s: %s", email, exc, exc_info=True)
        await msg.edit_text(f"⚠️ Internal error: {exc}")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle CSV file uploads for bulk verification."""
    document: Document = update.message.document

    if not document.file_name.lower().endswith(".csv"):
        await update.message.reply_text("Please upload a `.csv` file with an `email` column.")
        return

    status_msg = await update.message.reply_text("📥 Downloading file…")

    # Download file contents
    file = await context.bot.get_file(document.file_id)
    raw_bytes = await file.download_as_bytearray()

    # Parse CSV
    try:
        text    = raw_bytes.decode("utf-8-sig")
        reader  = csv.DictReader(io.StringIO(text))
        headers = [h.strip().lower() for h in (reader.fieldnames or [])]
        if "email" not in headers:
            await status_msg.edit_text(
                "❌ No `email` column found.\n"
                f"Headers detected: `{', '.join(reader.fieldnames or [])}`",
                parse_mode="Markdown",
            )
            return

        # Map original header name (preserving case) to "email"
        orig_header = next(h for h in reader.fieldnames if h.strip().lower() == "email")
        emails = [row[orig_header].strip() for row in reader if row.get(orig_header, "").strip()]

    except Exception as exc:
        await status_msg.edit_text(f"❌ Could not parse CSV: {exc}")
        return

    if not emails:
        await status_msg.edit_text("❌ No email addresses found in the file.")
        return

    if len(emails) > MAX_EMAILS_PER_UPLOAD:
        await status_msg.edit_text(
            f"❌ Too many emails ({len(emails)}). Maximum is {MAX_EMAILS_PER_UPLOAD}."
        )
        return

    await status_msg.edit_text(f"⚙️ Verifying {len(emails)} email(s)… please wait.")

    # Verify all emails
    results = []
    for i, email in enumerate(emails, 1):
        if i % 20 == 0:
            try:
                await status_msg.edit_text(f"⚙️ Progress: {i}/{len(emails)}…")
            except Exception:
                pass
        try:
            r = verify_email(email)
        except Exception as exc:
            logger.error("Error on %s: %s", email, exc)
            from verifier import VerificationResult, Confidence
            r = VerificationResult(
                email=email, status=Status.UNKNOWN,
                confidence=Confidence.LOW, mx_server_used="",
                notes=f"Internal error: {exc}",
            )
        results.append(r)
        time.sleep(0.3)   # polite delay

    # Build result CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=OUTPUT_FIELDS)
    writer.writeheader()
    for r in results:
        writer.writerow({
            "email":          r.email,
            "status":         r.status.value,
            "confidence":     r.confidence.value,
            "mx_server_used": r.mx_server_used,
            "notes":          r.notes,
        })

    csv_bytes = output.getvalue().encode("utf-8")

    # Summary stats
    counts = {}
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1

    summary_lines = [f"✅ Done! {len(results)} emails verified.\n"]
    for status, count in sorted(counts.items()):
        emoji = STATUS_EMOJI.get(Status(status), "")
        summary_lines.append(f"{emoji} {status}: {count}")

    await status_msg.edit_text("\n".join(summary_lines))

    # Send results file
    await update.message.reply_document(
        document=io.BytesIO(csv_bytes),
        filename="verification_results.csv",
        caption="📊 Full results attached.",
    )


# ── Bot startup ───────────────────────────────────────────────────────────────

def main() -> None:
    _setup_logging()

    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        logger.error(
            "No bot token set. Set TELEGRAM_BOT_TOKEN env var or edit bot.py"
        )
        raise SystemExit(1)

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",  cmd_start))
    app.add_handler(CommandHandler("help",   cmd_help))
    app.add_handler(CommandHandler("verify", cmd_verify))
    app.add_handler(MessageHandler(filters.Document.MimeType("text/csv"), handle_document))

    logger.info("Bot started — polling for updates…")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
