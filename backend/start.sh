#!/bin/bash

# Wait for database to be ready
echo "Waiting for database..."
python -c "
import time
import psycopg2
while True:
    try:
        import os
        pw = os.environ.get('POSTGRES_PASSWORD', 'password')
        conn = psycopg2.connect(f\"host=db port=5432 user=user password={pw} dbname=bug_bounty_db\")
        conn.close()
        break
    except:
        time.sleep(1)
"
echo "Database is ready"

# Run migrations
alembic upgrade head

# Start the application
uvicorn app.main:app --host 0.0.0.0 --port 8000