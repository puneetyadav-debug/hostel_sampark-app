# Hostel Sampark

A Flask app for submitting, tracking, and managing hostel grievances.

## Run on macOS

1. Install Python 3 and (optionally) Node.js. Open Terminal in this project folder.
2. Create and activate a virtual environment:

   ```sh
   python3 -m venv venv
   source venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

3. Create a `.env` file in the project folder with the values from your Supabase project:

   ```env
   FLASK_SECRET_KEY=use-a-long-random-secret
   ADMIN_USERNAME=your-admin-name
   ADMIN_PASSWORD=your-admin-password
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_SECRET_KEY=your-supabase-server-secret
   ```

   `SUPABASE_SECRET_KEY` is used by the Flask server for grievance submissions, private ticket lookups, and admin actions. Keep it server-side in `.env` and never put it in a template or commit it.

4. In the Supabase SQL Editor, run the SQL files in `supabase/migrations/` in filename order. The first adds the private-code verifier column; the second enables Row Level Security and removes direct table permissions from the `anon` and `authenticated` roles. The Flask server uses `SUPABASE_SECRET_KEY` to access the table.

5. Start the app:

   ```sh
   python app.py
   ```

6. Open <http://127.0.0.1:5000> in the browser.

If the error says a setting is not set in the environment, add that exact name to `.env`. If Python reports a missing module, activate `venv` and install `requirements.txt` again. For a database connection error, verify the Supabase URL/key and that the project is reachable.

To rebuild the CSS after changing Tailwind styles, install Node.js, run `npm install`, then `npm run build:css`. The checked-in CSS already lets you run the app without Node.js.

## Render session and CSRF settings

On Render, `RENDER=true` makes the app issue secure HTTPS-only session cookies automatically. Set `FLASK_SECRET_KEY` in the Render service environment to a long, random value and keep it unchanged between deploys and instances. Changing it invalidates existing sessions. The app now gives its session cookie a fresh name and marks HTML pages as non-cacheable so browsers do not reuse stale forms.

After deploying this update, visit `/admin-login` again and sign in. If the error continues, check that Render has one stable `FLASK_SECRET_KEY` value and that the browser is using the same `https://hostel-sampark-app.onrender.com` host for both loading and submitting the form.
