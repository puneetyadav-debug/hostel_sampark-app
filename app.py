import hmac
import logging
import os
import re
import hashlib
import secrets
from pathlib import Path
from typing import Optional
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from groq import Groq
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from supabase import create_client, Client
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

load_dotenv(dotenv_path=Path(__file__).resolve().with_name(".env"), override=False)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
groq_api_key = os.getenv("GROQ_API_KEY", "").strip()
groq_client = Groq(api_key=groq_api_key) if groq_api_key else None
logger = logging.getLogger(__name__)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],
)

def get_required_setting(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is not set in the environment.")
    return value


render_cookie_secure_default = os.getenv("RENDER", "").lower() == "true"
cookie_secure_setting = os.getenv("COOKIE_SECURE", "").strip().lower()
secure_cookie_values = {"1", "true", "yes"}

app.config.update(
    SECRET_KEY=get_required_setting("FLASK_SECRET_KEY"),
    # A new name forces browsers to establish a fresh session cookie after this fix.
    SESSION_COOKIE_NAME="hostel_sampark_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        render_cookie_secure_default or cookie_secure_setting in secure_cookie_values
    ),
    MAX_CONTENT_LENGTH=32 * 1024,
)

# Do not let a browser or intermediary reuse a form with a stale session token.
@app.after_request
def prevent_html_page_caching(response):
    if response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store, no-cache, max-age=0, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# Enable CSRF Protection for all form submissions.
csrf_protection = CSRFProtect(app)

# Credentials strictly loaded from environment
ADMIN_USERNAME = get_required_setting("ADMIN_USERNAME")
ADMIN_PASSWORD = get_required_setting("ADMIN_PASSWORD")

supabase_url: str = get_required_setting("SUPABASE_URL")
admin_database_key = os.getenv("SUPABASE_SECRET_KEY", "").strip()
admin_database: Optional[Client] = create_client(supabase_url, admin_database_key) if admin_database_key else None
ADMIN_PAGE_SIZE = 20


def admin_credential_version() -> str:
    credentials = f"{ADMIN_USERNAME}\0{ADMIN_PASSWORD}".encode()
    return hmac.new(app.config["SECRET_KEY"].encode(), credentials, "sha256").hexdigest()


def parse_ticket_id(ticket_id_text: Optional[str]) -> Optional[int]:
    """Parse the integer identity used by the grievance table."""
    ticket_id_text = (ticket_id_text or "").strip()
    if len(ticket_id_text) > 19 or not re.fullmatch(r"[0-9]+", ticket_id_text):
        return None
    ticket_id = int(ticket_id_text)
    return ticket_id if 0 < ticket_id <= 9223372036854775807 else None


def is_admin_logged_in():
    if session.get("admin_logged_in") is not True:
        return False

    saved_version = session.get("admin_credential_version", "")
    return hmac.compare_digest(saved_version, admin_credential_version())

@app.template_filter("local_datetime")
def format_local_datetime(value):
    if not value:
        return "Not available"

    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))

    return value.astimezone(ZoneInfo("Asia/Kolkata")).strftime(
        "%d %b %Y, %I:%M %p"
    )

@app.route("/")
def home():
    settings = {
        "hostels": "Saramati, Aravali, Geetanjali",
        "announcement": "Welcome to Hostel Sampark!",
        "portal_open": "true",
        "emergency_contacts": "",
    }

    if admin_database is not None:
        try:
            result = (
                admin_database.table("app_settings")
                .select("key, value")
                .execute()
            )

            for row in result.data or []:
                if row["key"] in settings:
                    settings[row["key"]] = row["value"]

        except Exception:
            logger.exception("Failed to load public settings")

    return render_template("landing.html", settings=settings)

def is_portal_open():
    if admin_database is None:
        return True

    try:
        result = (
            admin_database.table("app_settings")
            .select("value")
            .eq("key", "portal_open")
            .limit(1)
            .execute()
        )
        rows = result.data or []

        # If no setting exists, keep the portal open by default.
        if not rows:
            return True

        return rows[0]["value"].strip().lower() == "true"

    except Exception:
        logger.exception("Failed to check portal status")
        # Keep submissions available if the status can't be checked.
        return True

def is_ai_assistant_enabled():
    """Check if the admin has enabled the AI assistant."""
    if admin_database is None:
        return True
    try:
        res = admin_database.table("app_settings").select("value").eq("key", "ai_assistant_enabled").limit(1).execute()
        rows = res.data or []
        if not rows:
            return True
        return rows[0]["value"].strip().lower() == "true"
    except Exception:
        return True

@app.context_processor
def inject_global_settings():
    """Make ai_assistant_enabled automatically available to all HTML templates."""
    return {
        "ai_assistant_enabled": is_ai_assistant_enabled()
    }

def get_configured_hostels():
    default_hostels = ["Saramati", "Aravali", "Geetanjali"]

    if admin_database is None:
        return default_hostels

    try:
        result = (
            admin_database.table("app_settings")
            .select("value")
            .eq("key", "hostels")
            .limit(1)
            .execute()
        )

        rows = result.data or []
        if not rows:
            return default_hostels

        hostels = [
            name.strip()
            for name in rows[0]["value"].split(",")
            if name.strip()
        ]
        return hostels or default_hostels

    except Exception:
        logger.exception("Failed to load configured hostels")
        return default_hostels

def get_configured_categories():
    default_categories = ["Plumbing", "Electrical", "Internet", "Mess", "Furniture", "Cleanliness", "Pest Control", "Security", "Fees", "Interpersonal", "Ragging", "Others"]

    if admin_database is None:
        return default_categories

    try:
        result = (
            admin_database.table("app_settings")
            .select("value")
            .eq("key", "categories")
            .limit(1)
            .execute()
        )
        rows = result.data or []
        if not rows:
            return default_categories

        categories = [
            name.strip()
            for name in rows[0]["value"].split(",")
            if name.strip()
        ]
        return categories or default_categories

    except Exception:
        logger.exception("Failed to load configured categories")
        return default_categories

def get_ai_system_prompt():
    """Build the guardrail prompt with live hostel settings from the database."""
    hostels_list = ", ".join(get_configured_hostels())
    categories_list = ", ".join(get_configured_categories())
    
    # Fetch emergency contacts from settings
    emergency_contacts = "Check with hostel security desk."
    if admin_database is not None:
        try:
            res = admin_database.table("app_settings").select("value").eq("key", "emergency_contacts").limit(1).execute()
            if res.data and res.data[0]["value"].strip():
                emergency_contacts = res.data[0]["value"].strip()
        except Exception:
            pass

    return (
        "You are 'Sampark Sahayak', the official AI assistant for Hostel Sampark.\n"
        "Your sole job is to help hostel students with grievance submissions, maintenance procedures, and emergency contacts.\n"
        f"Active Hostels: {hostels_list}\n"
        f"Issue Categories: {categories_list}\n"
        f"Emergency Contacts: {emergency_contacts}\n\n"
        "STRICT GUARDRAILS:\n"
        "1. Describe only features that currently exist in Hostel Sampark. Students can submit a grievance using the website's Submit form and track it using the Track page with their ticket ID and private code.\n"
        "2. You cannot submit grievances, look up live grievance statuses, accept uploads, or send emails. Do not claim that you can.\n"
        "3. Never invent website steps, apps, email addresses, phone numbers, contacts, policies, or response-time promises. Use only the settings listed above. If a detail is missing, say you do not have it and direct the student to the website or hostel administration.\n"
        "4. Keep answers brief, polite, and easy to read on a small screen. Use short paragraphs or bullet points, with each item on a new line. Do not use tables.\n"
        "5. For questions about homework, exams, coding, politics, general trivia, or creative writing, politely say: "
        "'I am here only to assist with Hostel Sampark and student grievances.'"
    )

@app.route("/api/v1/config", methods=["GET"])
@csrf_protection.exempt
@limiter.limit("100 per minute")
def api_config():
    return jsonify({
        "hostels": get_configured_hostels(),
        "categories": get_configured_categories(),
        "portal_open": is_portal_open(),
        "ai_open": is_ai_assistant_enabled(),
    })

@app.route("/api/v1/submit", methods=["POST"])
@csrf_protection.exempt
@limiter.limit("100 per minute")
def api_submit_grievance():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Send a JSON object."}), 400

    title = data.get("title", "")
    description = data.get("description", "")
    hostel = data.get("hostel", "")
    category = data.get("category", "")

    if not all(isinstance(value, str) for value in [title, description, hostel, category]):
        return jsonify({"error": "All fields must be text."}), 400

    title = title.strip()
    description = description.strip()
    hostel = hostel.strip()
    category = category.strip()

    if not is_portal_open():
        return jsonify({"error": "Submissions are currently closed."}), 403
    if hostel not in get_configured_hostels():
        return jsonify({"error": "Choose a valid hostel."}), 400
    if category not in get_configured_categories():
        return jsonify({"error": "Choose a valid category."}), 400
    if not title or len(title) > 150:
        return jsonify({"error": "Title must be between 1 and 150 characters."}), 400
    if not description or len(description) > 2000:
        return jsonify({"error": "Description must be between 1 and 2000 characters."}), 400
    if admin_database is None:
        return jsonify({"error": "Submission storage is not configured."}), 503

    lookup_code = secrets.token_urlsafe(32)
    lookup_token_hash = hashlib.sha256(lookup_code.encode("utf-8")).hexdigest()

    try:
        result = admin_database.table("grievance").insert({
            "title": title,
            "description": description,
            "hostel": hostel,
            "category": category,
            "status": "Pending",
            "lookup_token_hash": lookup_token_hash,
        }).execute()

        grievance = result.data[0] if result.data else None
        if grievance is None:
            return jsonify({"error": "The complaint was saved, but no ticket ID was returned."}), 500

        return jsonify({
            "ticket_id": grievance["id"],
            "lookup_code": lookup_code,
        }), 201

    except Exception:
        logger.exception("API complaint submission failed")
        return jsonify({"error": "Could not save the complaint."}), 500

@app.route("/api/v1/status", methods=["POST"])
@csrf_protection.exempt
@limiter.limit("100 per minute")
def api_grievance_status():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Send a JSON object."}), 400

    ticket_id = parse_ticket_id(data.get("ticket_id"))
    lookup_code = data.get("lookup_code", "")

    if ticket_id is None or not isinstance(lookup_code, str) or not lookup_code.strip():
        return jsonify({"error": "A valid ticket_id and lookup_code are required."}), 400

    if admin_database is None:
        return jsonify({"error": "Complaint lookup is not configured."}), 503

    lookup_token_hash = hashlib.sha256(
        lookup_code.strip().encode("utf-8")
    ).hexdigest()

    try:
        result = (
            admin_database.table("grievance")
            .select("status, admin_notes")
            .eq("id", ticket_id)
            .eq("lookup_token_hash", lookup_token_hash)
            .limit(1)
            .execute()
        )

        grievance = result.data[0] if result.data else None
        if grievance is None:
            return jsonify({"error": "No complaint found for those details."}), 404

        return jsonify({
            "ticket_id": ticket_id,
            "status": grievance.get("status"),
            "admin_remarks": grievance.get("admin_notes") or "",
        })

    except Exception:
        logger.exception("API complaint status lookup failed")
        return jsonify({"error": "Could not look up the complaint."}), 500

@app.route("/submit", methods=["GET", "POST"])
def submit_grievance():
    if not is_portal_open():
        flash("Grievance submissions are currently closed.", "error")
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template(
            "index.html",
            hostels=get_configured_hostels(),
            categories=get_configured_categories(),
        )
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    hostel = request.form.get("hostel", "").strip()
    category = request.form.get("category", "").strip()
    if hostel not in get_configured_hostels():
        flash("Choose a valid hostel from the list.", "error")
        return redirect(url_for("submit_grievance"))
    if category not in get_configured_categories():
        flash("Choose a valid issue category from the list.", "error")
        return redirect(url_for("submit_grievance"))
    # Input validation: length limits for both title and description
    if not title or len(title) > 150:
        flash("Title must be between 1 and 150 characters.", "error")
        return redirect(url_for("submit_grievance"))
        
    if not description or len(description) > 2000:
        flash("Description must be between 1 and 2000 characters.", "error")
        return redirect(url_for("submit_grievance"))

    if admin_database is None:
        flash("Grievance submission needs SUPABASE_SECRET_KEY configured on the server.", "error")
        return redirect(url_for("submit_grievance"))
    
    lookup_code = secrets.token_urlsafe(32)
    lookup_token_hash = hashlib.sha256(
        lookup_code.encode("utf-8")
    ).hexdigest()
    
    data = {
        "title": title,
        "hostel": hostel,
        "description": description,
        "category": category,
        "status": "Pending",
        "lookup_token_hash": lookup_token_hash,
    }

    try:
        database_result = admin_database.table("grievance").insert(data).execute()
        grievance = database_result.data[0] if database_result.data else None
        if grievance is None:
            flash("The grievance was saved, but its ticket ID could not be returned.", "error")
            return redirect(url_for("submit_grievance"))
        # The template needs the submitted details and ID, never the verifier.
        grievance.pop("lookup_token_hash", None)
        return render_template("submitted.html", grievance=grievance, lookup_code=lookup_code)
    except Exception:
        logger.exception("Failed to save grievance")
        flash("An error occurred while saving your grievance.", "error")
        return redirect(url_for("submit_grievance"))


@app.route("/status", methods=["GET", "POST"])
def grievance_status():
    searched = request.method == "POST"
    searched_id = request.form.get("ticket_id", "").strip() if searched else ""
    lookup_code = request.form.get("lookup_code", "").strip() if searched else ""

    grievance = None
    invalid_lookup = False
    lookup_failed = False

    if searched:
        ticket_id = parse_ticket_id(searched_id)

        if ticket_id is None or not lookup_code:
            invalid_lookup = True
        elif admin_database is None:
            lookup_failed = True
            flash("Private grievance lookup is not configured. Contact the administrator.", "error")
        else:
            lookup_token_hash = hashlib.sha256(
                lookup_code.encode("utf-8")
            ).hexdigest()

            try:
                database_result = (
                    admin_database.table("grievance")
                    .select("id, title, hostel, description, category, admin_notes, status, created_at, updated_at")
                    .eq("id", ticket_id)
                    .eq("lookup_token_hash", lookup_token_hash)
                    .limit(1)
                    .execute()
                )
                grievance = database_result.data[0] if database_result.data else None
                invalid_lookup = grievance is None
            except Exception:
                lookup_failed = True
                logger.exception("Failed to look up grievance")

    return render_template(
        "status.html",
        searched=searched,
        searched_id=searched_id,
        grievance=grievance,
        invalid_ticket_id=invalid_lookup,
        lookup_failed=lookup_failed,
    )

@app.route("/admin-login", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("100 per 15 minutes")
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if hmac.compare_digest(username or "", ADMIN_USERNAME) and hmac.compare_digest(password or "", ADMIN_PASSWORD):
            session.clear()
            session["admin_logged_in"] = True
            session["admin_credential_version"] = admin_credential_version()
            return redirect(url_for("admin"))
        else:
            flash("Invalid credentials.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
def admin():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    page = request.args.get("page", default=1, type=int) or 1
    page = min(max(page, 1), 1_000_000)
    has_next_page = False

    if admin_database is None:
        grievances = []
        flash("Admin database access needs SUPABASE_SECRET_KEY configured on the server.", "error")
    else:
        try:
            offset = (page - 1) * ADMIN_PAGE_SIZE
            database_result = (
                admin_database.table("grievance")
                .select("id, title, hostel, description, category, admin_notes, status, created_at, updated_at")
                .order("created_at", desc=True)
                .order("id", desc=True)
                .range(offset, offset + ADMIN_PAGE_SIZE)
                .execute()
            )
            grievance_rows = database_result.data or []
            has_next_page = len(grievance_rows) > ADMIN_PAGE_SIZE
            grievances = grievance_rows[:ADMIN_PAGE_SIZE]
        except Exception:
            logger.exception("Failed to load grievances")
            grievances = []
            flash("Failed to load grievances. Check the server key and database access policies.", "error")

    return render_template(
        "admin.html",
        grievances=grievances,
        admin_db_configured=admin_database is not None,
        page=page,
        has_next_page=has_next_page,
    )

@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    if admin_database is None:
        flash("Admin settings need SUPABASE_SECRET_KEY configured on the server.", "error")
        return redirect(url_for("admin"))

    setting_keys = ("hostels", "announcement", "portal_open", "categories", "emergency_contacts", "ai_assistant_enabled")

    try:
        if request.method == "POST":
            # Read the submitted form values.
            values = {
                "hostels": request.form.get("hostels", "").strip(),
                "announcement": request.form.get("announcement", "").strip(),
                "portal_open": "true" if request.form.get("portal_open") == "true" else "false",
                "categories": request.form.get("categories", "").strip(),
                "emergency_contacts": request.form.get("emergency_contacts", "").strip(),
                "ai_assistant_enabled": "true" if request.form.get("ai_assistant_enabled") == "true" else "false",
            }

            # Upsert each setting row in Supabase so missing keys are created automatically.
            now_iso = datetime.now(timezone.utc).isoformat()
            for key in setting_keys:
                admin_database.table("app_settings").upsert(
                    {
                        "key": key,
                        "value": values[key],
                        "updated_at": now_iso,
                    },
                    on_conflict="key",
                ).execute()

            flash("Settings updated successfully!", "success")
            return redirect(url_for("admin_settings"))

        # Load the current settings to fill in the form.
        result = (
            admin_database.table("app_settings")
            .select("key, value")
            .execute()
        )
        settings = {row["key"]: row["value"] for row in (result.data or [])}

        # Provide defaults if a row is missing.
        settings.setdefault("hostels", "")
        settings.setdefault("announcement", "")
        settings.setdefault("portal_open", "true")
        settings.setdefault("emergency_contacts", "")
        settings.setdefault(
            "categories",
            "Plumbing, Electrical, Internet, Mess, Furniture, Cleanliness, Pest Control, Security, Fees, Interpersonal, Ragging, Others",
        )
        settings.setdefault("ai_assistant_enabled", "true")

        return render_template("admin_settings.html", settings=settings)

    except Exception:
        logger.exception("Failed to load or save admin settings")
        flash("Could not load or save settings. Check the server key and database access.", "error")
        return redirect(url_for("admin"))

@app.route("/update-status", methods=["POST"])
def update_status():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    ticket_id = parse_ticket_id(request.form.get("ticket_id"))
    new_status = request.form.get("new_status", "").strip()
    admin_notes = request.form.get("admin_notes", "").strip()
    page = request.form.get("page", default=1, type=int) or 1
    page = min(max(page, 1), 1_000_000)

    if ticket_id is None:
        flash("Invalid numeric ticket ID.", "error")
        return redirect(url_for("admin", page=page))

    # Strict whitelist status validation
    if new_status not in {"Pending", "In Progress", "Resolved"}:
        flash("Choose a valid grievance status.", "error")
        return redirect(url_for("admin", page=page))

    if len(admin_notes) > 1000:
        flash("Staff remarks must be 1000 characters or fewer.", "error")
        return redirect(url_for("admin", page=page))

    if admin_database is None:
        flash("Status updates need SUPABASE_SECRET_KEY configured on the server.", "error")
        return redirect(url_for("admin", page=page))

    try:
        database_result = (
            admin_database.table("grievance")
            .update({
                "status": new_status,
                "admin_notes": admin_notes,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            .eq("id", ticket_id)
            .select("id")
            .execute()
        )
        if not database_result.data:
            flash("No grievance was found for that ticket ID.", "error")
        else:
            flash("Grievance status updated.", "success")
    except Exception:
        logger.exception("Failed to update grievance status")
        flash("Update failed.", "error")

    return redirect(url_for("admin", page=page))


@app.route("/delete-grievance", methods=["POST"])
def delete_grievance():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    ticket_id = parse_ticket_id(request.form.get("ticket_id"))
    page = request.form.get("page", default=1, type=int) or 1
    page = min(max(page, 1), 1_000_000)

    if ticket_id is None:
        flash("Invalid numeric ticket ID.", "error")
        return redirect(url_for("admin", page=page))

    if admin_database is None:
        flash("Deleting grievances needs SUPABASE_SECRET_KEY configured on the server.", "error")
        return redirect(url_for("admin", page=page))

    try:
        database_result = (
            admin_database.table("grievance")
            .delete()
            .eq("id", ticket_id)
            .eq("status", "Resolved")
            .select("id")
            .execute()
        )
        if not database_result.data:
            flash("Only resolved grievances can be deleted, and no matching record was found.", "error")
        else:
            flash("Resolved grievance deleted.", "success")
    except Exception:
        logger.exception("Failed to delete grievance")
        flash("Delete failed.", "error")

    return redirect(url_for("admin", page=page))

@app.route("/api/chat", methods=["POST"])
@csrf_protection.exempt
@limiter.limit("100 per minute")
def api_chat():
    if groq_client is None:
        return jsonify({"error": "AI Assistant is not configured on the server."}), 503

    if not is_ai_assistant_enabled():
        return jsonify({"error": "AI Assistant is not enabled."}), 403

    data = request.get_json(silent=True) or {}
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "Please type a message."}), 400

    if len(user_message) > 500:
        return jsonify({"error": "Message is too long (maximum 500 characters)."}), 400

    try:
        response = groq_client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[
                {"role": "system", "content": get_ai_system_prompt()},
                {"role": "user", "content": user_message},
            ],
            max_tokens=600,
        )
        reply = response.choices[0].message.content
        return jsonify({"reply": reply})

    except Exception:
        logger.exception("Failed to generate AI response")
        return jsonify({"error": "AI assistant is temporarily unavailable. Please try again shortly."}), 500

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "").lower() in {"1", "true", "yes"})
