"""
Intentionally vulnerable backend for the IDOR teaching lab.

This app demonstrates an Insecure Direct Object Reference (IDOR) on the
POST /api/media/<id>/edit endpoint: it checks that the caller is logged in,
but never checks that the caller actually *owns* the post being edited.

DO NOT deploy this anywhere public. It is deliberately broken.
"""

import os
import time

from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Fixed secret so sessions survive container restarts. Fine for a lab,
# never do this in production.
app.config["SECRET_KEY"] = "insecure-lab-secret-key-do-not-use-in-prod"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql://idor:idor@db:5432/idordb"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)


class Post(db.Model):
    """A 'post' / piece of media. Its primary key is the `media_id` that the
    vulnerable endpoint trusts blindly."""

    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    caption = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(512), nullable=False, default="")

    def to_dict(self):
        return {
            "media_id": self.id,
            "owner_id": self.owner_id,
            "owner": User.query.get(self.owner_id).username,
            "caption": self.caption,
            "image_url": self.image_url,
        }


# ---------------------------------------------------------------------------
# One-time seeding
# ---------------------------------------------------------------------------
def seed():
    if User.query.count() > 0:
        return

    victim = User(username="victim", password_hash=generate_password_hash("victim123"))
    attacker = User(username="attacker", password_hash=generate_password_hash("attacker123"))
    db.session.add_all([victim, attacker])
    db.session.commit()

    # Random photos served by Lorem Picsum (https://picsum.photos). The `seed`
    # keeps each post's image stable across restarts.
    # Explicit, long media IDs so they look like real-world object references
    # (and so swapping one for another in Burp is the obvious move).
    db.session.add_all(
        [
            Post(id=100123, owner_id=victim.id, caption="My first sunset 🌅",
                 image_url="https://picsum.photos/seed/sunset/600/400"),
            Post(id=100456, owner_id=victim.id, caption="Coffee art this morning ☕",
                 image_url="https://picsum.photos/seed/coffee/600/400"),
            Post(id=200789, owner_id=attacker.id, caption="Mountain hike views ⛰️",
                 image_url="https://picsum.photos/seed/mountain/600/400"),
            Post(id=200987, owner_id=attacker.id, caption="New gadget unboxing 📦",
                 image_url="https://picsum.photos/seed/gadget/600/400"),
        ]
    )
    db.session.commit()


def init_db():
    """Wait for Postgres, then create tables and seed sample data."""
    for _ in range(30):
        try:
            with app.app_context():
                db.create_all()
                seed()
            return
        except OperationalError:
            time.sleep(1)
    raise RuntimeError("Database not reachable after 30 attempts")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    return User.query.get(uid) if uid else None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.post("/api/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    user = User.query.filter_by(username=data.get("username", "")).first()
    if not user or not check_password_hash(user.password_hash, data.get("password", "")):
        return jsonify({"error": "invalid credentials"}), 401
    session["user_id"] = user.id
    return jsonify({"username": user.username, "user_id": user.id})


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"error": "not logged in"}), 401
    return jsonify({"username": user.username, "user_id": user.id})


@app.get("/api/posts")
def list_posts():
    """The public feed — shows everyone's posts."""
    posts = Post.query.order_by(Post.id).all()
    return jsonify([p.to_dict() for p in posts])


@app.get("/api/media/<int:media_id>")
def get_media(media_id):
    """Used by the edit form to pre-fill the current caption."""
    post = Post.query.get(media_id)
    if not post:
        return jsonify({"error": "not found"}), 404
    return jsonify(post.to_dict())


@app.post("/api/media/<int:media_id>/edit")
def edit_media(media_id):
    """
    *** THE VULNERABLE ENDPOINT ***

    It correctly requires the caller to be authenticated, but it NEVER checks
    that the authenticated user owns `media_id`. Any logged-in user can edit
    any post just by changing the id in the URL — a textbook IDOR.
    """
    user = current_user()
    if not user:
        return jsonify({"error": "authentication required"}), 401

    post = Post.query.get(media_id)
    if not post:
        return jsonify({"error": "not found"}), 404

    # ---------------------------------------------------------------
    # THE MISSING CHECK. This is the entire bug. Uncomment to fix it:
    #
    # if post.owner_id != user.id:
    #     return jsonify({"error": "forbidden — you do not own this post"}), 403
    # ---------------------------------------------------------------

    data = request.get_json(force=True, silent=True) or {}
    new_caption = data.get("caption")
    if new_caption is None:
        return jsonify({"error": "caption required"}), 400

    post.caption = new_caption
    db.session.commit()
    return jsonify(post.to_dict())


@app.get("/api/health")
def health():
    return jsonify({"ok": True})


# Seed at import time so the gunicorn worker has data ready.
init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
