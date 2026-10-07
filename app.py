from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cyberguard-demo-secret")
DB = os.path.join(os.path.dirname(__file__), "cyberguard.db")

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT, name TEXT,
      email TEXT, role TEXT, department TEXT, password TEXT
    );
    CREATE TABLE IF NOT EXISTS devices(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, hostname TEXT,
      mac TEXT, ip TEXT, os TEXT, health TEXT
    );
    CREATE TABLE IF NOT EXISTS threats(
      id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, name TEXT,
      severity TEXT, score REAL, source_ip TEXT, destination_ip TEXT,
      status TEXT, timestamp TEXT
    );
    CREATE TABLE IF NOT EXISTS incidents(
      id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id INTEGER,
      analyst TEXT, priority TEXT, status TEXT, notes TEXT, updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS scores(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
      points INTEGER, remark TEXT, audit_date TEXT
    );
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id INTEGER,
      message TEXT, read_status TEXT, sent_at TEXT
    );
    """)
    if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        c.executemany("INSERT INTO users(employee_id,name,email,role,department,password) VALUES(?,?,?,?,?,?)",[
            ("EMP-8821","Sarah Jenkins","s.jenkins@cyber.io","Analyst","Cyber Defense","admin123"),
            ("EMP-4402","Marcus Vance","m.vance@cyber.io","Administrator","Infrastructure","admin123"),
            ("EMP-9011","Elena Rostova","e.rostova@cyber.io","Auditor","Compliance","admin123"),
        ])
        c.executemany("INSERT INTO devices(user_id,hostname,mac,ip,os,health) VALUES(?,?,?,?,?,?)",[
            (1,"WKSTN-SEC-01","00:1A:2C:38:4F:11","192.168.1.45","Windows 11 Pro","Healthy"),
            (2,"SRV-DB-PRIMARY","00:1A:2C:38:4F:88","10.0.4.12","Ubuntu 22.04 LTS","Critical"),
            (1,"LAPTOP-REM-09","02:42:AC:11:00:02","172.16.2.110","macOS Sonoma","Warning"),
        ])
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.executemany("""INSERT INTO threats(device_id,name,severity,score,source_ip,destination_ip,status,timestamp)
                         VALUES(?,?,?,?,?,?,?,?)""",[
            (2,"SQL Injection Attack","Critical",9.4,"185.220.101.5","10.0.4.12","Detected",now),
            (3,"SSH Brute Force","High",8.1,"194.26.29.114","172.16.2.110","Quarantined",now),
            (1,"Port Scan Detected","Medium",5.2,"45.154.255.82","192.168.1.45","Resolved",now),
        ])
        c.executemany("INSERT INTO incidents(threat_id,analyst,priority,status,notes,updated_at) VALUES(?,?,?,?,?,?)",[
            (1,"Sarah Jenkins","Critical","Investigating","IP blocked at perimeter firewall.",now),
            (2,"Sarah Jenkins","High","Mitigated","Rate-limiting and temporary IP ban applied.",now),
            (3,"Sarah Jenkins","Medium","Closed","Harmless external scan; rules updated.",now),
        ])
        c.executemany("INSERT INTO scores(user_id,points,remark,audit_date) VALUES(?,?,?,?)",[
            (1,98,"Fully Compliant - MFA & Patching Up to Date","2024-03-01"),
            (2,72,"Action Required: Missing OS Critical Patch","2024-03-01"),
            (3,91,"Compliant - Hardware Token Verified","2024-03-01"),
        ])
        c.commit()
    c.close()

@app.route("/", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form["email"]; password=request.form["password"]
        c=db(); u=c.execute("SELECT * FROM users WHERE email=? AND password=?",(email,password)).fetchone(); c.close()
        if u:
            session["user"]=dict(u)
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid demo credentials.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if "user" not in session: return redirect(url_for("login"))
    c=db()
    stats={
      "total": c.execute("SELECT COUNT(*) FROM threats").fetchone()[0],
      "critical": c.execute("SELECT COUNT(*) FROM threats WHERE severity='Critical'").fetchone()[0],
      "high": c.execute("SELECT COUNT(*) FROM threats WHERE severity='High'").fetchone()[0],
      "resolved": c.execute("SELECT COUNT(*) FROM threats WHERE status='Resolved'").fetchone()[0]
    }
    threats=c.execute("""SELECT t.*,d.hostname FROM threats t JOIN devices d ON d.id=t.device_id
                         ORDER BY t.id DESC""").fetchall()
    devices=c.execute("SELECT * FROM devices ORDER BY id").fetchall()
    incidents=c.execute("""SELECT i.*,t.name threat_name FROM incidents i
                           JOIN threats t ON t.id=i.threat_id ORDER BY i.id DESC""").fetchall()
    scores=c.execute("""SELECT s.*,u.name FROM scores s JOIN users u ON u.id=s.user_id""").fetchall()
    c.close()
    return render_template("dashboard.html", user=session["user"], stats=stats,
                           threats=threats, devices=devices, incidents=incidents, scores=scores)

@app.post("/threat")
def add_threat():
    if "user" not in session: return redirect(url_for("login"))
    data=request.form
    sev=data["severity"]
    score={"Low":2.5,"Medium":5.2,"High":8.1,"Critical":9.5}[sev]
    now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c=db()
    c.execute("""INSERT INTO threats(device_id,name,severity,score,source_ip,destination_ip,status,timestamp)
                 VALUES(?,?,?,?,?,?,?,?)""",
              (int(data["device_id"]),data["name"],sev,score,data["source_ip"],
               data["destination_ip"],"Detected",now))
    tid=c.execute("SELECT last_insert_rowid()").fetchone()[0]
    if sev in ("High","Critical"):
        c.execute("""INSERT INTO incidents(threat_id,analyst,priority,status,notes,updated_at)
                     VALUES(?,?,?,?,?,?)""",(tid,session["user"]["name"],sev,"Investigating","Auto-created from high-risk threat.",now))
        c.execute("""INSERT INTO alerts(threat_id,message,read_status,sent_at)
                     VALUES(?,?,?,?)""",(tid,f"{sev} threat detected: {data['name']}","Unread",now))
    c.commit(); c.close()
    return redirect(url_for("dashboard"))

@app.post("/incident/<int:iid>")
def update_incident(iid):
    if "user" not in session: return redirect(url_for("login"))
    status=request.form["status"]; notes=request.form.get("notes","")
    c=db(); c.execute("UPDATE incidents SET status=?,notes=?,updated_at=? WHERE id=?",
                      (status,notes,datetime.now().strftime("%Y-%m-%d %H:%M:%S"),iid)); c.commit(); c.close()
    return redirect(url_for("dashboard"))

@app.post("/device/<int:did>/quarantine")
def quarantine(did):
    if "user" not in session: return redirect(url_for("login"))
    c=db(); c.execute("UPDATE devices SET health='Quarantined' WHERE id=?", (did,)); c.commit(); c.close()
    return redirect(url_for("dashboard"))

@app.get("/api/threats")
def api_threats():
    c=db(); rows=c.execute("SELECT * FROM threats ORDER BY id DESC").fetchall(); c.close()
    return jsonify([dict(r) for r in rows])

if __name__=="__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
