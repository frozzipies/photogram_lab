# 📷 PhotoGram — IDOR Teaching Lab

An intentionally vulnerable mini "Instagram" built to demonstrate a classic
**Insecure Direct Object Reference (IDOR)** bug for a beginner bug-bounty video.

A logged-in user can **edit another user's post** simply by changing the
`media_id` in an API request. The server checks that you're *logged in* but
never checks that you *own* the post — the exact mistake behind many real
bug-bounty reports.

> ⚠️ **This app is deliberately insecure. Run it locally only. Never deploy it.**

---

## What's inside

| Service    | Tech                       | Role                                            |
|------------|----------------------------|-------------------------------------------------|
| `frontend` | nginx + plain HTML/JS      | Login page, feed, edit form. Proxies `/api/*`.  |
| `backend`  | Python + Flask + SQLAlchemy| The API, including the vulnerable endpoint.     |
| `db`       | PostgreSQL 16              | Pre-seeded with 2 users and 4 posts.            |

Everything runs through one origin — `http://localhost:8080` — so Burp Suite
sees a single clean host and session cookies "just work."

### Pre-seeded accounts

| Username   | Password      | Role                  | Posts (media_id)                          |
|------------|---------------|-----------------------|-------------------------------------------|
| `victim`   | `victim123`   | gets their post edited | 100123 → "My first sunset 🌅", 100456 → "Coffee art this morning ☕" |
| `attacker` | `attacker123` | logs in and tampers    | 200789 → "Mountain hike views ⛰️", 200987 → "New gadget unboxing 📦" |

---

## Run it

> **Run locally only.** This app is intentionally vulnerable, so you can't (and
> shouldn't) host it on a public server or on GitHub itself. GitHub stores the
> source; you run it on your own machine.

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) with the
Docker Compose plugin (Docker Desktop includes it).

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/photogram_lab.git
cd photogram_lab

# 2. Build and start the lab
docker compose up --build
```

Then open **http://localhost:8080**.

To reset the database to its original seeded state:

```bash
docker compose down -v && docker compose up --build
```

---

## The vulnerability

The edit endpoint lives in `backend/app.py`:

```python
@app.post("/api/media/<int:media_id>/edit")
def edit_media(media_id):
    user = current_user()
    if not user:
        return jsonify({"error": "authentication required"}), 401   # ✅ checks login

    post = Post.query.get(media_id)
    if not post:
        return jsonify({"error": "not found"}), 404

    # ❌ MISSING: no check that post.owner_id == user.id

    post.caption = request.get_json()["caption"]
    db.session.commit()
    return jsonify(post.to_dict())
```

The endpoint authenticates the caller but **authorizes nothing**. The
`media_id` comes straight from the URL and is trusted blindly. That gap —
*authentication without authorization* — is what IDOR is.

The frontend even hides the "Edit" link on posts you don't own, which makes it
look safe. But that's a **client-side** restriction; the server is the only
thing that actually matters, and it doesn't enforce ownership.

---

## Reproduce the attack (step by step)

You'll play the **attacker** editing the **victim's** post (media_id `100123`).

### Option A — with Burp Suite (the realistic workflow)

1. **Start the lab:** `docker compose up --build`, open http://localhost:8080.
2. **Point your browser at Burp** and make sure *Intercept* is on
   (Proxy → Intercept → "Intercept is on").
3. **Log in as attacker** (`attacker` / `attacker123`).
4. **Find the victim's media_id.** Click the victim's post in the feed. It opens
   its dedicated page at `/post.html?id=100123` — the `media_id` is right there
   in the address bar. There's no Edit button (it isn't yours), but you now have
   the **direct object reference** (`100123`) you'll abuse.
5. Go back to the feed and click **✏️ Edit your post** on one of the
   **attacker's own** posts (media_id `200789` or `200987`), change the caption,
   and click **Save changes**.
6. Burp catches the request. It looks like:

   ```http
   POST /api/media/200789/edit HTTP/1.1
   Host: localhost:8080
   Content-Type: application/json
   Cookie: session=...

   {"caption":"my edited caption"}
   ```

7. **Tamper with it:** change the path from `/api/media/200789/edit` to
   `/api/media/100123/edit` (the victim's post). Optionally change the caption
   to something obvious like `"HACKED by attacker 😈"`.
8. **Forward** the request (and turn Intercept off).
9. Go back to the feed and refresh. **The victim's post now shows the
   attacker's text**, even though the attacker never owned it. 🎯

### Option B — with `curl` (no Burp needed)

```bash
# 1. Log in as the attacker, saving the session cookie
curl -s -c cookies.txt -X POST http://localhost:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"attacker","password":"attacker123"}'

# 2. Edit the VICTIM's post (media_id 100123) while authenticated as the attacker
curl -s -b cookies.txt -X POST http://localhost:8080/api/media/100123/edit \
  -H 'Content-Type: application/json' \
  -d '{"caption":"HACKED by attacker 😈"}'

# 3. Confirm: the victim's post now carries the attacker's caption
curl -s http://localhost:8080/api/posts
```

The response to step 2 returns `"owner": "victim"` with the attacker's new
caption — proof the ownership check is missing.

---

## The secure fix

Add an **ownership (authorization) check** after authentication. In
`backend/app.py`, uncomment the guard already left in place:

```python
@app.post("/api/media/<int:media_id>/edit")
def edit_media(media_id):
    user = current_user()
    if not user:
        return jsonify({"error": "authentication required"}), 401

    post = Post.query.get(media_id)
    if not post:
        return jsonify({"error": "not found"}), 404

    # ✅ THE FIX: reject edits to posts the caller does not own.
    if post.owner_id != user.id:
        return jsonify({"error": "forbidden — you do not own this post"}), 403

    post.caption = request.get_json()["caption"]
    db.session.commit()
    return jsonify(post.to_dict())
```

After uncommenting, rebuild (`docker compose up --build`) and repeat the attack:
the attacker now gets **`403 Forbidden`** when targeting the victim's `media_id`.

### General principles for avoiding IDOR

- **Authentication ≠ authorization.** "Who are you?" is not "are you allowed to
  touch *this* object?" Always check both.
- **Enforce ownership on the server**, on every object-referencing request.
  Never rely on the UI hiding a button.
- **Scope queries to the user** where possible, e.g.
  `Post.query.filter_by(id=media_id, owner_id=user.id).first()` returns nothing
  for someone else's object, so the check is built into the lookup.
- **Don't "fix" it by hiding IDs.** Swapping sequential IDs for UUIDs makes
  guessing harder but is *not* an access-control fix — the missing check is.
- **Test authorization** with two accounts: can user B act on user A's objects?

---

## Project layout

```
photogram_lab/
├── docker-compose.yml
├── README.md
├── LICENSE
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py          # ← the vulnerable endpoint + the commented fix
└── frontend/
    ├── nginx.conf      # serves static files, proxies /api → backend
    ├── style.css
    ├── index.html      # login page
    ├── feed.html       # feed of all posts (each links to its post page)
    ├── post.html       # dedicated single-post page (media_id shows in the URL)
    └── edit.html       # edit form (the request you intercept)
```
