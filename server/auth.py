import os
import re

import psycopg
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash


DATABASE_URL = os.environ.get("DATABASE_URL")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def get_connection():
	if not DATABASE_URL:
		raise RuntimeError("Set DATABASE_URL to a PostgreSQL connection string.")
	return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def ensure_users_table():
	with get_connection() as connection:
		connection.execute(
			"""
			CREATE TABLE IF NOT EXISTS users (
				id BIGSERIAL PRIMARY KEY,
				username VARCHAR(40) UNIQUE NOT NULL,
				email VARCHAR(254) UNIQUE NOT NULL,
				password_hash TEXT NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
			)
			"""
		)


def create_user(username, email, password):
	if not USERNAME_PATTERN.fullmatch(username):
		raise ValueError("Username may contain letters, numbers, dots, dashes, and underscores only.")

	password_hash = generate_password_hash(password)
	try:
		with get_connection() as connection:
			return connection.execute(
				"""
				INSERT INTO users (username, email, password_hash)
				VALUES (%s, %s, %s)
				RETURNING id, username
				""",
				(username, email, password_hash),
			).fetchone()
	except psycopg.errors.UniqueViolation as error:
		if "email" in str(error).lower():
			raise ValueError("An account with that email already exists.") from error
		raise ValueError("That username is already taken.") from error


def authenticate_user(identifier, password):
	with get_connection() as connection:
		user = connection.execute(
			"""
			SELECT id, username, password_hash
			FROM users
			WHERE username = %s OR email = %s
			""",
			(identifier, identifier.lower()),
		).fetchone()

	if user and check_password_hash(user["password_hash"], password):
		return user
	return None






















