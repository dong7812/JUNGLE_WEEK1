import smtplib, ssl, time, secrets, os
import requests 
import re
import jwt
import json
import traceback

from flask import Flask, render_template, jsonify, request, session, make_response, redirect, url_for, g
from flask.json.provider import JSONProvider
from pymongo import MongoClient
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from dotenv import load_dotenv
from bson import ObjectId
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps


load_dotenv()

SENDER    = os.environ.get('SMTP_USER')
SENDERPW  = os.environ.get('SMTP_PASS')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

TTL_SEC = 10 * 60

UA = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/122.0.0.0 Safari/537.36"),
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
    "Referer": "https://www.google.com/"
}

# client = MongoClient('mongodb://dlehdrb020:dl71727812!@54.180.80.148', 27017)
client = MongoClient('localhost', 27017)  # mongoDB는 27017 포트로 돌아갑니다.
db = client.dbjungle
posts_col = db.posts

@app.route('/')
def home():
    posts = list(posts_col.find().sort("_id", -1).limit(20))
    return render_template('main.html', posts = posts)

# --- JWT 관련 함수 (헤더 방식) ---


def get_current_user():
    if hasattr(g, 'user'):
        return g.user

    # Authorization 헤더에서 Bearer 토큰 꺼내기
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ')[1]
    if not token:
        return None

    try:
        # JWT 디코드
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        user_id = payload.get('user_id')
        if not user_id:
            return None

        # MongoDB에서 해당 유저 조회
        try:
            user = db.user.find_one({"_id": ObjectId(user_id)})
        except Exception:
            # 만약 ObjectId 변환이 안 된다면 문자열 비교
            user = db.user.find_one({"_id": user_id})

        if user:
            g.user = user
            return user
        return None

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# --- 로그인 필수 데코레이터 ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # [수정] get_current_user()를 직접 호출하는 대신 토큰 존재 여부로 확인
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            if request.accept_mimetypes.accept_html:
                return redirect(url_for('login_page', next=request.url))
            return jsonify({'result': 'fail', 'message': '로그인이 필요합니다.'}), 401
        return f(*args, **kwargs)
    return decorated_function

# 회원가입
@app.route('/add/user', methods=['POST'])
def add_user():
    uid = request.form.get('uid', '')
    pw = request.form.get('pw', '')
    name = request.form.get('name', '')
    email = request.form.get('email', '')

    # 비밀번호 해싱
    password_hash = generate_password_hash(pw)

    user = {
        'uid': uid,
        'password_hash': password_hash,
        'username': name,   # JWT에서 username으로 쓰려면 name을 username 필드로 저장
        'email': email
    }

    db.user.insert_one(user)

    return jsonify({'result': 'success'})

@app.route('/do/login', methods=['POST'])
def do_login():
    try:
        data = request.get_json()
        uid = data.get('uid')
        password = data.get('password')
        
        print(f"uid :", uid)

        user = db.user.find_one({"uid": uid})

        if user and check_password_hash(user['password_hash'], password):
            payload = {
                'user_id': str(user['_id']),
                'username': user.get('username', ''),  # KeyError 방지
                'exp': datetime.now(timezone.utc) + timedelta(hours=int(app.config.get('JWT_EXPIRATION_HOURS', 1)))
            }
            token = jwt.encode(payload, os.environ.get('SECRET_KEY', 'dev-secret'), algorithm='HS256')
            session['uid'] = uid
            return jsonify({'result': 'success', 'message': '로그인 성공', 'token': token})
        else:
            return jsonify({'result': 'fail', 'message': '이메일 또는 비밀번호가 올바르지 않습니다.'}), 401
    except Exception as e:
        
        traceback.print_exc()
        return jsonify({'result': 'error', 'message': str(e)}), 500

# --- [수정] 로그아웃 라우트 추가 ---
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    return response

@app.route('/chat')
def chat():
    return render_template('popup/chat.html')

# 인증 코드 전송
@app.route('/code/send', methods=['POST'])
def code_send():
    to_email = (request.form.get('email') or '').strip()
    subject  = (request.form.get('content') or '').strip()
    html     = (request.form.get('html') or '').strip()
    
    if not to_email or not subject or not html:
        return jsonify(ok=False, msg='email/content/html required'), 400
    
    now = int(time.time())
    code = f"{secrets.randbelow(900000)+100000:06d}"  # 6자리
    issued = now
    
    session["verify_code"] = code
    session["verify_time"] = issued

    try:
        msg = MIMEMultipart('alternative')
        msg['From'], msg['To'], msg['Subject'] = SENDER, to_email, subject
        msg.attach(MIMEText(re.sub(r"verified", code, html), 'html', 'utf-8'))

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(SENDER, SENDERPW)
            s.send_message(msg)

        return jsonify(ok=True, msg='sent')
    except Exception as e:
        app.logger.exception("send failed: %s", e)
        return jsonify(ok=False, msg='failed to send'), 500
    
#인증 코드 확인
@app.route('/code/verified', methods=['POST'])
def compare_code():
    input_code = (request.form.get('input') or '').strip()

    # 세션에서 값 읽기
    real_code = session.get('verify_code')
    real_code_time = session.get('verify_time')


    # 먼저 기본 검증
    if not real_code or not real_code_time:
        return jsonify(ok=False, msg='not requested'), 404

    now = int(time.time())

    # 만료 체크
    if now - int(real_code_time) > TTL_SEC:
        # 만료되면 세션 정리
        session.pop('verify_code', None)
        session.pop('verify_time', None)
        session.pop('verify_attempts', None)
        return jsonify(ok=False, msg='expired'), 400

    # 코드 비교 (문자열 비교 권장)
    if str(input_code) == str(real_code):
        session.pop('verify_code', None)
        session.pop('verify_time', None)
        session.pop('verify_attempts', None)
        session['email_verified'] = True
        return jsonify(ok=True, msg='verified')
    
#비밀번호 재설정
@app.route('/pw/reset', methods=['POST'])
def reset_pw():
    newPassword = (request.form.get('password') or '').strip()
    email = (request.form.get('email') or '').strip()
    
    password_hash = generate_password_hash(newPassword)
    
    result = db.user.update_one({'email': email}, {"$set": {'password_hash': password_hash}})
    
    if(result.modified_count > 0):
        return jsonify({'result': 'success'})        
    else :
        return jsonify({'result': 'fail'})
    
#ID 찾기
@app.route('/id/find', methods=['POST'])
def find_id():
    to_email = (request.form.get('email') or '').strip()
    name = (request.form.get('name') or '').strip()
    subject  = (request.form.get('content') or '').strip()
    html     = (request.form.get('html') or '').strip()
    
    if not to_email or not subject or not html:
        return jsonify(ok=False, msg='email/content/html required'), 400
    
    doc = db.user.find_one(
    {"email": to_email, "name": name},
    {"_id": 0, "uid": 1}   # 프로젝션: uid만
    )
    
    uid = doc["uid"] if doc else None

    try:
        msg = MIMEMultipart('alternative')
        msg['From'], msg['To'], msg['Subject'] = SENDER, to_email, subject
        msg.attach(MIMEText(re.sub(r"findId", uid, html), 'html', 'utf-8'))

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(SENDER, SENDERPW)
            s.send_message(msg)

        return jsonify(ok=True, msg='sent')
    except Exception as e:
        app.logger.exception("send failed: %s", e)
        return jsonify(ok=False, msg='failed to send'), 500
    
@app.route("/posting", methods=["GET"])
def posting():
    return render_template("/popup/posting.html")

# 글 생성
@app.route("/api/posts", methods=["POST"])
def create_post():
    payload = request.get_json(force=True, silent=True) or {}
    userID   = (payload.get("userID") or "").strip()
    category = (payload.get("category") or "").strip()
    title    = (payload.get("title") or "").strip()
    time_    = (payload.get("time") or "").strip()
    people   = int(payload.get("people") or 0)
    tag      = (payload.get("tag") or "").strip()
    url      = (payload.get("url") or "").strip()
    meta_image = ""
    createdAt = datetime.utcnow()

    doc = {
        "userID": userID,
        "title": title,
        "category": category,
        "tag": tag,
        "url": url,
        "time": time_,
        "people": people,
        "currentParticipants": 1,          # 글쓴이 포함
        "participants": [userID],          # 글쓴이 자동 참여
        "meta_image": meta_image,
        "createdAt": createdAt,
    }
    result = posts_col.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    doc["createdAt"] = createdAt.isoformat()
    return jsonify(success=True, post=doc), 201


# 상세 글
@app.route("/api/posts/<_id>", methods=["GET"])
def get_post(_id):
    try:
        oid = ObjectId(_id)
    except Exception:
        return jsonify(success=False, msg="invalid id"), 400

    doc = posts_col.find_one({"_id": oid})
    if not doc:
        return jsonify(success=False), 404

    doc["_id"] = str(doc["_id"])
    if isinstance(doc.get("createdAt"), datetime):
        doc["createdAt"] = doc["createdAt"].isoformat()
    return jsonify(success=True, post=doc), 200


# 참여하기
@app.route("/api/posts/<_id>/join", methods=["POST"])
def join_post(_id):
    user_id = request.json.get("userID")
    if not user_id:
        return jsonify(success=False, msg="missing userID"), 400

    try:
        oid = ObjectId(_id)
    except Exception:
        return jsonify(success=False, msg="invalid id"), 400

    doc = posts_col.find_one({"_id": oid})
    if not doc:
        return jsonify(success=False, msg="not found"), 404

    if user_id in doc.get("participants", []):
        return jsonify(success=False, msg="already joined"), 400

    if doc.get("currentParticipants", 0) >= doc.get("people", 0):
        return jsonify(success=False, msg="full"), 400

    updated = posts_col.find_one_and_update(
        {"_id": oid},
        {
            "$inc": {"currentParticipants": 1},
            "$addToSet": {"participants": user_id}
        },
        return_document=True
    )
    updated["_id"] = str(updated["_id"])
    return jsonify(success=True, post=updated), 200


# 참여 취소
@app.route("/api/posts/<_id>/leave", methods=["POST"])
def leave_post(_id):
    user_id = request.json.get("userID")
    if not user_id:
        return jsonify(success=False, msg="missing userID"), 400

    try:
        oid = ObjectId(_id)
    except Exception:
        return jsonify(success=False, msg="invalid id"), 400

    doc = posts_col.find_one({"_id": oid})
    if not doc:
        return jsonify(success=False, msg="not found"), 404

    if user_id not in doc.get("participants", []):
        return jsonify(success=False, msg="not joined"), 400

    updated = posts_col.find_one_and_update(
        {"_id": oid},
        {
            "$inc": {"currentParticipants": -1},
            "$pull": {"participants": user_id}
        },
        return_document=True
    )
    updated["_id"] = str(updated["_id"])
    return jsonify(success=True, post=updated), 200

# 글 목록
@app.route("/api/posts", methods=["GET"])
def list_posts():
    docs = []
    for d in posts_col.find().sort("createdAt", -1):
        d["_id"] = str(d["_id"])
        if isinstance(d.get("createdAt"), datetime):
            d["createdAt"] = d["createdAt"].isoformat()
        docs.append(d)
    return jsonify(success=True, posts=docs), 200

def extract_meta_image(page_url: str) -> str:
    try:
        r = requests.get(page_url, headers=UA, timeout=8, allow_redirects=True)
        r.raise_for_status()
    except Exception:
        return ""
    real_url = r.url
    soup = BeautifulSoup(r.text, "html.parser")
    # 1) og/twitter/link 우선
    for sel in ['meta[property="og:image"]',
                'meta[property="og:image:secure_url"]',
                'meta[name="twitter:image"]',
                'link[rel="image_src"]']:
        tag = soup.select_one(sel)
        if not tag:
            continue
        raw = _pick_lazy_src(tag)
        if not raw:
            continue
        if raw.startswith("//"):
            raw = "https:" + raw
        cand = urljoin(real_url, raw)
        if _is_image_url(cand):
            return cand
    # 2) 대표 이미지 후보 스캔
    hints = ("main", "product", "goods", "thumb", "detail", "gallery", "image")
    imgs = []
    for img in soup.find_all("img"):
        cls = " ".join(img.get("class", []))
        id_ = img.get("id", "")
        if any(h in (cls + id_).lower() for h in hints):
            imgs.append(img)
    if not imgs:
        imgs = soup.find_all("img")
    for img in imgs[:30]:
        raw = _pick_lazy_src(img)
        if not raw:
            continue
        if raw.startswith("//"):
            raw = "https:" + raw
        cand = urljoin(real_url, raw)
        if _is_image_url(cand):
            return cand
    return ""

def _pick_lazy_src(tag):
    return _first(
        tag.get("content"), tag.get("src"), tag.get("data-src"),
        tag.get("data-original"), tag.get("data-lazy"),
        tag.get("data-url"), tag.get("href"),
    )
    
def _is_image_url(u: str) -> bool:
    try:
        h = requests.head(u, headers=UA, timeout=5, allow_redirects=True)
        ct = h.headers.get("Content-Type", "")
        return h.ok and ct.startswith("image/")
    except Exception:
        return False

def _first(*vals):
    for v in vals:
        if v and str(v).strip():
            return str(v).strip()
    return "" 

@app.route("/check/id", methods=["POST"])
def check_id():
    uid = request.form.get("uid")
    if not uid:
        return jsonify({"ok": False, "msg": "no uid"}), 400

    # DB에서 해당 uid 존재 여부 확인
    existing = db.user.find_one({"uid": uid})
    
    if existing:
        # 이미 존재하는 아이디
        return jsonify({"ok": False, "msg": "duplicated"})
    else:
        # 사용 가능한 아이디
        return jsonify({"ok": True, "msg": "available"})


@app.route("/detail/<_id>", methods=["GET"])
def detail_page(_id):
    item = None
    try:
        # ObjectId로 변환 가능한 경우에만 시도
        oid = ObjectId(_id)
        item = posts_col.find_one({"_id": oid})
    except Exception:
        # 문자열형 _id를 쓰는 설계라면 여기서 다시 시도해도 됨
        item = posts_col.find_one({"_id": _id})
    if not item:
        return render_template("404.html", message="해당 상품을 찾을 수 없습니다.")
    # 템플릿에서 쓰기 편하도록 문자열로 변환
    item["_id"] = str(item["_id"])
    if isinstance(item.get("createdAt"), datetime):
        item["createdAt"] = item["createdAt"].isoformat()
    return render_template("/product/detail.html", item=item)

@app.route("/login")
def login():
    return render_template("sign_in/login.html")

@app.route("/join")
def join():
    return render_template("sign_in/join.html")

@app.route("/reset_pw")
def to_reset_pw():
    return render_template("sign_in/reset_pw.html")

@app.route("/find_id")
def to_find_id():
    return render_template("sign_in/find_id.html")

@app.route("/mypage")
def to_my_page():
    uid = session.get("uid")
    return render_template("mypage/mypage.html", uid=uid)
    
if __name__ == '__main__':
    app.run('0.0.0.0', port=5001, debug=True)