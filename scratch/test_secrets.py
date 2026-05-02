import os
# Correct length AWS Key (20 chars)
AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_PASSWORD = os.getenv("DB_PASSWORD")
