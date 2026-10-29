import hmac
import logging
import os
import re
from pathlib import Path
from typing import Optional
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv(dotenv_path=Path(__file__).resolve().with_name(".env"), override=False)

app = Flask(__name__)
logger = logging.getLogger(__name__)

def required_setting(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is not set in the environment.")
    return value


app.config.update(
    SECRET_KEY=required_setting("FLASK_SECRET_KEY"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "").lower() in {"1", "true", "yes"},
    MAX_CONTENT_LENGTH=32 * 1024,
)

# Enable CSRF Protection for all form submissions
csrf = CSRFProtect(app)

# Credentials strictly loaded from environment
ADMIN_USERNAME = required_setting("ADMIN_USERNAME")
ADMIN_PASSWORD = required_setting("ADMIN_PASSWORD")

url: str = required_setting("SUPABASE_URL")
key: str = required_setting("SUPABASE_KEY")
supabase: Client = create_client(url, key)
admin_key = os.getenv("SUPABASE_SECRET_KEY", "").strip()
admin_supabase: Optional[Client] = create_client(url, admin_key) if admin_key else None
ADMIN_PAGE_SIZE = 20


def admin_credential_version() -> str:
    credentials = f"{ADMIN_USERNAME}\0{ADMIN_PASSWORD}".encode()
    return hmac.new(app.config["SECRET_KEY"].encode(), credentials, "sha256").hexdigest()


def parse_ticket_id(value: Optional[str]) -> Optional[int]:
    """Parse the integer identity used by the grievance table."""
    value = (value or "").strip()
    if len(value) > 19 or not re.fullmatch(r"[0-9]+", value):
        return None
    ticket_id = int(value)
    return ticket_id if 0 < ticket_id <= 9223372036854775807 else None


def is_admin_logged_in():
    if session.get("admin_logged_in") is not True:
        return False

    saved_version = session.get("admin_credential_version", "")
    return hmac.compare_digest(saved_version, admin_credential_version())


@app.route("/")
def home():
    return render_template("landing.html")


@app.route("/submit", methods=["GET", "POST"])
def submit_grievance():
    if request.method == "GET":
        return render_template("index.html")
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()

    # Input validation: length limits for both title and description
    if not title or len(title) > 150:
        flash("Title must be between 1 and 150 characters.", "error")
        return redirect(url_for("submit_grievance"))
        
    if not description or len(description) > 2000:
        flash("Description must be between 1 and 2000 characters.", "error")
        return redirect(url_for("submit_grievance"))

    data = {
        "title": title,
        "description": description,
        "status": "Pending"
    }

    try:
        response = supabase.table("grievance").insert(data).execute()
        grievance = response.data[0] if response.data else None
        if grievance is None:
            flash("The grievance was saved, but its ticket ID could not be returned.", "error")
            return redirect(url_for("submit_grievance"))
        return render_template("submitted.html", grievance=grievance)
    except Exception:
        logger.exception("Failed to save grievance")
        flash("An error occurred while saving your grievance.", "error")
        return redirect(url_for("submit_grievance"))


@app.route("/status", methods=["GET"])
def grievance_status():
    searched_id = request.args.get("ticket_id", "").strip()
    searched = "ticket_id" in request.args
    grievance = None
    invalid_ticket_id = False
    lookup_failed = False

    if searched:
        ticket_id = parse_ticket_id(searched_id)
        if ticket_id is None:
            invalid_ticket_id = True
            flash("Enter a valid numeric ticket ID.", "error")
        else:
            try:
                response = (
                    supabase.table("grievance")
                    .select("id, title, description, status, created_at")
                    .eq("id", ticket_id)
                    .limit(1)
                    .execute()
                )
                if response.data:
                    grievance = response.data[0]
            except Exception:
                lookup_failed = True
                logger.exception("Failed to look up grievance status")
                flash("Database communication error.", "error")

    return render_template(
        "status.html",
        searched=searched,
        searched_id=searched_id,
        grievance=grievance,
        invalid_ticket_id=invalid_ticket_id,
        lookup_failed=lookup_failed,
    )


@app.route("/admin-login", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
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

    if admin_supabase is None:
        grievances = []
        flash("Admin database access needs SUPABASE_SECRET_KEY configured on the server.", "error")
    else:
        try:
            offset = (page - 1) * ADMIN_PAGE_SIZE
            response = (
                admin_supabase.table("grievance")
                .select("*")
                .order("created_at", desc=True)
                .order("id", desc=True)
                .range(offset, offset + ADMIN_PAGE_SIZE)
                .execute()
            )
            rows = response.data or []
            has_next_page = len(rows) > ADMIN_PAGE_SIZE
            grievances = rows[:ADMIN_PAGE_SIZE]
        except Exception:
            logger.exception("Failed to load grievances")
            grievances = []
            flash("Failed to load grievances. Check the server key and database access policies.", "error")

    return render_template(
        "admin.html",
        grievances=grievances,
        admin_db_configured=admin_supabase is not None,
        page=page,
        has_next_page=has_next_page,
    )


@app.route("/update-status", methods=["POST"])
def update_status():
    if not is_admin_logged_in():
        return redirect(url_for("login"))

    ticket_id = parse_ticket_id(request.form.get("ticket_id"))
    new_status = request.form.get("new_status", "").strip()
    page = request.form.get("page", default=1, type=int) or 1
    page = min(max(page, 1), 1_000_000)

    if ticket_id is None:
        flash("Invalid numeric ticket ID.", "error")
        return redirect(url_for("admin", page=page))

    # Strict whitelist status validation
    if new_status not in {"Pending", "In Progress", "Resolved"}:
        flash("Choose a valid grievance status.", "error")
        return redirect(url_for("admin", page=page))

    if admin_supabase is None:
        flash("Status updates need SUPABASE_SECRET_KEY configured on the server.", "error")
        return redirect(url_for("admin", page=page))

    try:
        response = (
            admin_supabase.table("grievance")
            .update({"status": new_status})
            .eq("id", ticket_id)
            .select("id")
            .execute()
        )
        if not response.data:
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

    if admin_supabase is None:
        flash("Deleting grievances needs SUPABASE_SECRET_KEY configured on the server.", "error")
        return redirect(url_for("admin", page=page))

    try:
        response = (
            admin_supabase.table("grievance")
            .delete()
            .eq("id", ticket_id)
            .eq("status", "Resolved")
            .select("id")
            .execute()
        )
        if not response.data:
            flash("Only resolved grievances can be deleted, and no matching record was found.", "error")
        else:
            flash("Resolved grievance deleted.", "success")
    except Exception:
        logger.exception("Failed to delete grievance")
        flash("Delete failed.", "error")

    return redirect(url_for("admin", page=page))


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "").lower() in {"1", "true", "yes"})
