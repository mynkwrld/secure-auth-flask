# 🔐 Secure Authentication System (Flask + JWT)

A simple but secure authentication system built with **Python Flask**, **JWT (JSON Web Tokens)**, and **bcrypt** for password hashing.  
This project was created as part of my internship project.  

---

## ⚙️ Features
- ✅ User Registration with encrypted passwords  
- ✅ Secure Login with JWT tokens (access + refresh)  
- ✅ Token-based Authentication & Authorization  
- ✅ Session management (token expiry & refresh)  
- ✅ SQLite (default) or PostgreSQL support  

---

## 📋 Requirements
- Python 3.x  
- Flask  
- PyJWT  
- bcrypt  
- SQLAlchemy  
- python-dotenv  

(All dependencies are listed in `requirements.txt`)

---

## 🚀 Quick Start (One Command)
Clone repo, set up environment, install deps, init DB, and run server in one go:

```bash
git clone https://github.com/mynkwrld/secure-auth-flask.git
cd secure-auth-flask
bash run_local.sh
```

App will be running at:  
👉 [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🛠 API Usage Examples

### 🔹 1. Register User
**Endpoint:** `POST /register`  
**Request JSON:**
```json
{
  "username": "mayank",
  "password": "mypassword123"
}
```

**Response:**
```json
{
  "message": "User registered successfully!"
}
```

---

### 🔹 2. Login User
**Endpoint:** `POST /login`  
**Request JSON:**
```json
{
  "username": "mayank",
  "password": "mypassword123"
}
```

**Response:**
```json
{
  "access_token": "<JWT_ACCESS_TOKEN>",
  "refresh_token": "<JWT_REFRESH_TOKEN>"
}
```

---

### 🔹 3. Access Protected Route
**Endpoint:** `GET /protected`  
**Headers:**
```
Authorization: Bearer <JWT_ACCESS_TOKEN>
```

**Response (if token is valid):**
```json
{
  "message": "Welcome, mayank! You have accessed a protected route."
}
```

---

## 🗄 Database
- Default: **SQLite** (auto-created `app.db`)  
- For PostgreSQL, set `DATABASE_URL` in `.env`:  
```
DATABASE_URL=postgresql+psycopg2://username:password@localhost:5432/secure_auth_db
```

---

## 📂 Project Structure
```
secure-auth-flask/
│── app.py            # Main Flask app
│── requirements.txt  # Dependencies
│── .env.example      # Example environment file
│── run_local.sh      # One-shot setup script
│── README.md         # Project documentation
```

---

## 👤 Author
**Mayank Sharma**  
📅 Internship Project – 2025  

---

## ⭐ Contribute
If you like this project, don’t forget to **star ⭐ the repo** on GitHub!  
