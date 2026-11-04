import hashlib
import os
import unittest
from unittest.mock import patch

# app.py reads these settings while it is imported. Test-only defaults let the
# tests run even when a developer has not created a local .env file.
os.environ.setdefault("FLASK_SECRET_KEY", "test-only-secret")
os.environ.setdefault("ADMIN_USERNAME", "test-admin")
os.environ.setdefault("ADMIN_PASSWORD", "test-password")
os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")

import app as hostel_app


class FakeResult:
    def __init__(self, data):
        self.data = data


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows
        self.filters = {}
        self.inserted = None

    def insert(self, data):
        self.inserted = data
        return self

    def select(self, *_args):
        return self

    def eq(self, column, value):
        self.filters[column] = value
        return self

    def limit(self, *_args):
        return self

    def execute(self):
        if self.inserted is not None:
            return FakeResult([{"id": 123, **self.inserted}])
        matching_rows = [
            row for row in self.rows
            if all(row.get(column) == value for column, value in self.filters.items())
        ]
        return FakeResult(matching_rows)


class FakeDatabase:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.last_query = None

    def table(self, _name):
        self.last_query = FakeQuery(self.rows)
        return self.last_query


class TestApp(unittest.TestCase):
    """Check key routes without contacting the real Supabase project."""

    def setUp(self):
        hostel_app.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = hostel_app.app.test_client()

    def test_submit_saves_grievance_and_shows_ticket(self):
        database = FakeDatabase()
        with patch.object(hostel_app, "admin_database", database):
            response = self.client.post(
                "/submit",
                data={"title": "Broken light", "description": "The light is out."},
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"123", response.data)
        self.assertIn("lookup_token_hash", database.last_query.inserted)
        self.assertEqual(database.last_query.inserted["title"], "Broken light")
        self.assertEqual(database.last_query.inserted["status"], "Pending")

    def test_wrong_private_code_does_not_show_grievance(self):
        correct_code_hash = hashlib.sha256(b"right-code").hexdigest()
        database = FakeDatabase(
            [{"id": 123, "lookup_token_hash": correct_code_hash}]
        )
        with patch.object(hostel_app, "admin_database", database):
            response = self.client.post(
                "/status", data={"ticket_id": "123", "lookup_code": "wrong-code"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"couldn't find a grievance", response.data)
        self.assertNotIn(b"lookup_token_hash", response.data)

    def test_signed_out_user_is_redirected_from_admin(self):
        response = self.client.get("/admin")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_login_page_loads(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
