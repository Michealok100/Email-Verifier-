"""
Email Verification Telegram Bot — single-file version.
All modules bundled in. No external local imports needed.

Setup:
  pip install dnspython python-telegram-bot
  export TELEGRAM_BOT_TOKEN="your_token_here"
  python bot.py
"""

import csv
import io
import logging
import os
import random
import re
import smtplib
import socket
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import dns.resolver
import dns.exception
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

TELEGRAM_BOT_TOKEN: str     = os.environ.get("TELEGRAM_BOT_TOKEN", "8591866214:AAEh8NNLHQUKcLOH57MRH_tq2TDxduAA6r4")
DNS_TIMEOUT: float          = 5.0
SMTP_TIMEOUT: float         = 10.0
SMTP_CONNECT_TIMEOUT: float = 8.0
MAX_RETRIES: int            = 2
RETRY_DELAY: float          = 2.0
CATCHALL_PROBE_COUNT: int   = 1
CATCHALL_PREFIX_LENGTH: int = 20
HELO_HOSTNAME: str          = "mail-verify.example.com"
MAIL_FROM: str              = "verify@mail-verify.example.com"
LOG_FILE: str               = "email_verifier.log"
LOG_LEVEL: str              = "INFO"
MAX_EMAILS_PER_UPLOAD: int  = 500

# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════

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

# ══════════════════════════════════════════════════════════════════════════════
# SYNTAX VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

MAX_EMAIL_LENGTH  = 254
MAX_LOCAL_LENGTH  = 64
MAX_DOMAIN_LENGTH = 255

_LOCAL_UNQUOTED = r"[a-zA-Z0-9!#\$%&'*+/=?^_\`{|}~-]+"
_LOCAL_QUOTED   = r'"(?:[^"\\]|\\.)*"'
_LOCAL_PART     = rf"(?:{_LOCAL_UNQUOTED}(?:\.{_LOCAL_UNQUOTED})*|{_LOCAL_QUOTED})"
_DOMAIN_LABEL   = r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
_DOMAIN_PART    = rf"{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})+"
_EMAIL_REGEX    = re.compile(rf"^{_LOCAL_PART}@{_DOMAIN_PART}$")


@dataclass
class SyntaxResult:
    valid: bool
    local: str = ""
    domain: str = ""
    error: str = ""


def validate_syntax(email: str) -> SyntaxResult:
    email = email.strip()
    if not email:
        return SyntaxResult(valid=False, error="Empty string")
    if len(email) > MAX_EMAIL_LENGTH:
        return SyntaxResult(valid=False, error=f"Too long ({len(email)} > {MAX_EMAIL_LENGTH})")
    if email.count("@") != 1:
        return SyntaxResult(valid=False, error="Must contain exactly one '@'")
    local, domain = email.rsplit("@", 1)
    if len(local) > MAX_LOCAL_LENGTH:
        return SyntaxResult(valid=False, error="Local part too long")
    if len(domain) > MAX_DOMAIN_LENGTH:
        return SyntaxResult(valid=False, error="Domain too long")
    if not _EMAIL_REGEX.match(email):
        return SyntaxResult(valid=False, error="Failed RFC 5321 syntax check")
    tld = domain.rsplit(".", 1)[-1]
    if len(tld) < 2:
        return SyntaxResult(valid=False, error=f"Invalid TLD: '{tld}'")
    return SyntaxResult(valid=True, local=local, domain=domain.lower())


# ══════════════════════════════════════════════════════════════════════════════
# DNS / MX VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MXRecord:
    hostname: str
    priority: int


@dataclass
class DNSResult:
    domain: str
    valid: bool
    mx_records: List[MXRecord] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def sorted_mx(self) -> List[MXRecord]:
        return sorted(self.mx_records, key=lambda r: r.priority)


def validate_domain_dns(domain: str) -> DNSResult:
    domain = domain.strip().lower()
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(domain, "MX")
        mx_records = [
            MXRecord(hostname=str(r.exchange).rstrip("."), priority=r.preference)
            for r in answers
        ]
        return DNSResult(domain=domain, valid=True, mx_records=mx_records)
    except dns.resolver.NXDOMAIN:
        return DNSResult(domain=domain, valid=False, error="NXDOMAIN: domain does not exist")
    except dns.resolver.NoAnswer:
        return _check_a_record_fallback(domain, resolver)
    except dns.resolver.NoNameservers:
        return DNSResult(domain=domain, valid=False, error="No nameservers available")
    except dns.exception.Timeout:
        return DNSResult(domain=domain, valid=False, error="DNS timeout")
    except Exception as exc:
        return DNSResult(domain=domain, valid=False, error=str(exc))


def _check_a_record_fallback(domain: str, resolver: dns.resolver.Resolver) -> DNSResult:
    try:
        resolver.resolve(domain, "A")
        return DNSResult(
            domain=domain, valid=True,
            mx_records=[MXRecord(hostname=domain, priority=0)],
            error="No MX record; falling back to A record",
        )
    except Exception as exc:
        return DNSResult(domain=domain, valid=False, error=str(exc))


# ══════════════════════════════════════════════════════════════════════════════
# SMTP VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

class SMTPStatus(str, Enum):
    VALID     = "VALID"
    INVALID   = "INVALID"
    UNKNOWN   = "UNKNOWN"
    TEMPORARY = "TEMPORARY"


@dataclass
class SMTPResult:
    status: SMTPStatus
    smtp_code: Optional[int] = None
    mx_used: Optional[str] = None
    notes: str = ""


def verify_smtp(email: str, mx_hosts: List[str]) -> SMTPResult:
    last_result: Optional[SMTPResult] = None
    for attempt in range(MAX_RETRIES + 1):
        mx = mx_hosts[attempt % len(mx_hosts)]
        result = _probe_mailbox(email, mx)
        if result.status == SMTPStatus.TEMPORARY:
            last_result = result
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            continue
        return result
    if last_result:
        return SMTPResult(
            status=SMTPStatus.UNKNOWN,
            smtp_code=last_result.smtp_code,
            mx_used=last_result.mx_used,
            notes=f"Temporary rejection after {MAX_RETRIES + 1} attempts — possible greylisting",
        )
    return SMTPResult(status=SMTPStatus.UNKNOWN, notes="No MX hosts to try")


def _probe_mailbox(email: str, mx_host: str) -> SMTPResult:
    try:
        with smtplib.SMTP(timeout=SMTP_CONNECT_TIMEOUT) as smtp:
            smtp.connect(mx_host, 25)
            try:
                smtp.ehlo(HELO_HOSTNAME)
            except smtplib.SMTPHeloError:
                smtp.helo(HELO_HOSTNAME)
            code, _ = smtp.docmd(f"MAIL FROM:<{MAIL_FROM}>")
            if code not in (250, 251):
                return SMTPResult(status=SMTPStatus.UNKNOWN, smtp_code=code, mx_used=mx_host,
                                  notes="MAIL FROM rejected — server may be blocking verification")
            code, message = smtp.docmd(f"RCPT TO:<{email}>")
            msg_str = message.decode(errors="replace") if isinstance(message, bytes) else str(message)
            return _interpret_rcpt_response(code, msg_str, mx_host)
    except smtplib.SMTPConnectError as exc:
        return SMTPResult(status=SMTPStatus.UNKNOWN, mx_used=mx_host, notes=f"SMTP connect error: {exc}")
    except smtplib.SMTPServerDisconnected:
        return SMTPResult(status=SMTPStatus.UNKNOWN, mx_used=mx_host, notes="Server disconnected unexpectedly")
    except socket.timeout:
        return SMTPResult(status=SMTPStatus.UNKNOWN, mx_used=mx_host, notes="Connection timed out")
    except ConnectionRefusedError:
        return SMTPResult(status=SMTPStatus.UNKNOWN, mx_used=mx_host, notes="Connection refused — port 25 may be blocked")
    except OSError as exc:
        return SMTPResult(status=SMTPStatus.UNKNOWN, mx_used=mx_host, notes=f"Network error: {exc}")
    except Exception as exc:
        return SMTPResult(status=SMTPStatus.UNKNOWN, mx_used=mx_host, notes=f"Unexpected error: {exc}")


def _interpret_rcpt_response(code: int, message: str, mx_host: str) -> SMTPResult:
    if code in (250, 251, 252):
        return SMTPResult(status=SMTPStatus.VALID, smtp_code=code, mx_used=mx_host, notes="Mailbox accepted by server")
    if code in (421, 450, 451, 452):
        return SMTPResult(status=SMTPStatus.TEMPORARY, smtp_code=code, mx_used=mx_host, notes=f"Temporary rejection ({code}): {message[:120]}")
    if code in (550, 551, 552, 553, 554) or 500 <= code < 600:
        return SMTPResult(status=SMTPStatus.INVALID, smtp_code=code, mx_used=mx_host, notes=f"Mailbox rejected ({code}): {message[:120]}")
    return SMTPResult(status=SMTPStatus.UNKNOWN, smtp_code=code, mx_used=mx_host, notes=f"Unrecognised SMTP response ({code}): {message[:120]}")


# ══════════════════════════════════════════════════════════════════════════════
# CATCH-ALL DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def is_catch_all(domain: str, mx_hosts: List[str]) -> bool:
    for _ in range(CATCHALL_PROBE_COUNT):
        fake_local = "verify-probe-" + "".join(
            random.choices(string.ascii_lowercase + string.digits, k=CATCHALL_PREFIX_LENGTH)
        )
        fake_email = f"{fake_local}@{domain}"
        result = verify_smtp(fake_email, mx_hosts)
        if result.status == SMTPStatus.VALID:
            logger.info("Domain %s is CATCH-ALL", domain)
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# VERIFICATION ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class Status(str, Enum):
    VALID          = "VALID"
    INVALID        = "INVALID"
    RISKY          = "RISKY"
    UNKNOWN        = "UNKNOWN"
    DOMAIN_INVALID = "DOMAIN_INVALID"


class Confidence(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


@dataclass
class VerificationResult:
    email: str
    status: Status
    confidence: Confidence
    mx_server_used: str
    notes: str


OUTPUT_FIELDS = ["email", "status", "confidence", "mx_server_used", "notes"]


def verify_email(email: str) -> VerificationResult:
    email = email.strip().lower()

    syntax = validate_syntax(email)
    if not syntax.valid:
        return VerificationResult(email=email, status=Status.INVALID, confidence=Confidence.HIGH,
                                  mx_server_used="", notes=f"Syntax error: {syntax.error}")

    dns_result = validate_domain_dns(syntax.domain)
    if not dns_result.valid:
        return VerificationResult(email=email, status=Status.DOMAIN_INVALID, confidence=Confidence.HIGH,
                                  mx_server_used="", notes=f"DNS error: {dns_result.error}")

    mx_hosts   = [r.hostname for r in dns_result.sorted_mx]
    primary_mx = mx_hosts[0] if mx_hosts else ""

    domain_is_catchall = is_catch_all(syntax.domain, mx_hosts)
    smtp_result        = verify_smtp(email, mx_hosts)
    mx_used            = smtp_result.mx_used or primary_mx
    code_tag           = f" [SMTP {smtp_result.smtp_code}]" if smtp_result.smtp_code else ""

    if smtp_result.status == SMTPStatus.VALID:
        if domain_is_catchall:
            return VerificationResult(email=email, status=Status.RISKY, confidence=Confidence.LOW,
                                      mx_server_used=mx_used, notes=f"Catch-all domain{code_tag}")
        return VerificationResult(email=email, status=Status.VALID, confidence=Confidence.HIGH,
                                  mx_server_used=mx_used, notes=f"Mailbox confirmed{code_tag}")

    if smtp_result.status == SMTPStatus.INVALID:
        return VerificationResult(email=email, status=Status.INVALID, confidence=Confidence.HIGH,
                                  mx_server_used=mx_used, notes=f"{smtp_result.notes}{code_tag}")

    if domain_is_catchall:
        return VerificationResult(email=email, status=Status.RISKY, confidence=Confidence.LOW,
                                  mx_server_used=mx_used, notes=f"Catch-all; SMTP inconclusive — {smtp_result.notes}")

    return VerificationResult(email=email, status=Status.UNKNOWN, confidence=Confidence.LOW,
                              mx_server_used=mx_used, notes=f"SMTP inconclusive — {smtp_result.notes}{code_tag}")


# ══════════════════════════════════════════════════════════════════════════════
# TELEGRAM BOT HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

STATUS_EMOJI = {
    Status.VALID:          "✅",
    Status.INVALID:        "❌",
    Status.RISKY:          "⚠️",
    Status.UNKNOWN:        "❓",
    Status.DOMAIN_INVALID: "🚫",
}


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "👋 *Email Verification Bot*\n\n"
        "I verify email addresses for bounce reduction\\.\n\n"
        "*Commands:*\n"
        "`/verify user@example\\.com` — check a single email\n"
        "`/help` — show status explanations\n\n"
        "📎 *Bulk:* Upload a CSV file with an `email` column "
        "and I'll return a results CSV\\.",
        parse_mode="MarkdownV2",
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "📖 *Status guide:*\n\n"
        "✅ *VALID* — Mailbox confirmed \\(high confidence\\)\n"
        "❌ *INVALID* — Mailbox/domain rejected \\(high confidence\\)\n"
        "⚠️ *RISKY* — Catch\\-all domain; result uncertain\n"
        "❓ *UNKNOWN* — Server blocked probe; don't assume invalid\n"
        "🚫 *DOMAIN\\_INVALID* — Domain has no DNS/MX records\n\n"
        "⚠️ *Limitations:*\n"
        "• Gmail, Outlook, Yahoo block SMTP probing → UNKNOWN\n"
        "• Catch\\-all domains \\(many corporate\\) → RISKY\n"
        "• Results are probabilistic, not guaranteed",
        parse_mode="MarkdownV2",
    )


async def cmd_verify(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Usage: `/verify user@example.com`", parse_mode="Markdown")
        return

    email = context.args[0].strip()
    msg   = await update.message.reply_text(f"🔍 Verifying `{email}`…", parse_mode="Markdown")

    try:
        result = verify_email(email)
        emoji  = STATUS_EMOJI.get(result.status, "❓")

        def esc(t: str) -> str:
            return re.sub(r"([_*\[\]()~`>#+\-=|{}.!])", r"\\\1", t)

        text = (
            f"{emoji} *{result.status.value}* \\({result.confidence.value}\\)\n"
            f"📧 `{esc(result.email)}`\n"
        )
        if result.mx_server_used:
            text += f"🖥 MX: `{esc(result.mx_server_used)}`\n"
        if result.notes:
            text += f"📝 {esc(result.notes)}"

        await msg.edit_text(text, parse_mode="MarkdownV2")
    except Exception as exc:
        logger.error("Error verifying %s: %s", email, exc, exc_info=True)
        await msg.edit_text(f"⚠️ Internal error: {exc}")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document

    if not document.file_name.lower().endswith(".csv"):
        await update.message.reply_text("Please upload a `.csv` file with an `email` column.")
        return

    status_msg = await update.message.reply_text("📥 Downloading file…")
    file       = await context.bot.get_file(document.file_id)
    raw_bytes  = await file.download_as_bytearray()

    try:
        text        = raw_bytes.decode("utf-8-sig")
        reader      = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            await status_msg.edit_text("❌ CSV has no headers.")
            return
        orig_header = next((h for h in reader.fieldnames if h.strip().lower() == "email"), None)
        if not orig_header:
            await status_msg.edit_text(
                f"❌ No `email` column found.\nHeaders: `{', '.join(reader.fieldnames)}`",
                parse_mode="Markdown",
            )
            return
        emails = [row[orig_header].strip() for row in reader if row.get(orig_header, "").strip()]
    except Exception as exc:
        await status_msg.edit_text(f"❌ Could not parse CSV: {exc}")
        return

    if not emails:
        await status_msg.edit_text("❌ No email addresses found in the file.")
        return
    if len(emails) > MAX_EMAILS_PER_UPLOAD:
        await status_msg.edit_text(f"❌ Too many emails ({len(emails)}). Max is {MAX_EMAILS_PER_UPLOAD}.")
        return

    await status_msg.edit_text(f"⚙️ Verifying {len(emails)} email(s)… please wait.")

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
            r = VerificationResult(email=email, status=Status.UNKNOWN, confidence=Confidence.LOW,
                                   mx_server_used="", notes=f"Internal error: {exc}")
        results.append(r)
        time.sleep(0.3)

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

    counts = {}
    for r in results:
        counts[r.status.value] = counts.get(r.status.value, 0) + 1

    lines = [f"✅ Done! {len(results)} emails verified.\n"]
    for status, count in sorted(counts.items()):
        emoji = STATUS_EMOJI.get(Status(status), "")
        lines.append(f"{emoji} {status}: {count}")

    await status_msg.edit_text("\n".join(lines))
    await update.message.reply_document(
        document=io.BytesIO(output.getvalue().encode("utf-8")),
        filename="verification_results.csv",
        caption="📊 Full results attached.",
    )


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    _setup_logging()

    if TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        logger.error("No bot token set. Set TELEGRAM_BOT_TOKEN env var or edit bot.py")
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
