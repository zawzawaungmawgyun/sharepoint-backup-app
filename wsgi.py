import os
from app import app

# Expose the Flask application as 'app' for WSGI servers (e.g., gunicorn wsgi:app)
# Do not run the Flask dev server here; the WSGI server handles HTTP.

if __name__ == "__main__":
    # Optional: allow local run for sanity checks
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
