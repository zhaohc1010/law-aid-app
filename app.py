import os
import datetime
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import or_

# --- 1. 初始化和配置 ---
app = Flask(__name__)
app.secret_key = 'a_really_long_and_random_secret_string_for_production'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'project.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ITEMS_PER_PAGE'] = 10
ADMIN_PASSWORD = "password123"
STATUS_OPTIONS = ['待处理', '审阅中', '需补充材料', '已完成']
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


# --- 2. 数据库模型 ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    submissions = db.relationship('Submission', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    files = db.Column(db.String(500), nullable=False)
    report_file = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default=STATUS_OPTIONS[0])
    comments = db.relationship('Comment', backref='submission', lazy=True, cascade="all, delete-orphan")


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False)
    # ★★★ 新增的字段 ★★★
    read_by_user = db.Column(db.Boolean, default=False, nullable=False)
    read_by_admin = db.Column(db.Boolean, default=False, nullable=False)


# --- 3. 路由 ---
# ... (从 @app.route('/') 到 /logout 的路由无变化) ...
@app.route('/')
def index():
    if 'user_id' in session and not session.get('admin_logged_in'):
        return redirect(url_for('dashboard'))
    elif 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if username == 'admin_user':
            flash('该用户名是保留用户名，不可注册！', 'danger')
            return redirect(url_for('register'))
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('该用户名已被注册！', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('注册成功，请登录。', 'success')
        return redirect(url_for('user_login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        session.clear()
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.username != 'admin_user' and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'欢迎回来, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户名或密码错误！', 'danger')
            return redirect(url_for('user_login'))
    return render_template('user_login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('您已成功退出。', 'info')
    return redirect(url_for('user_login'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session or session.get('admin_logged_in'):
        return redirect(url_for('user_login'))
    if request.method == 'POST':
        current_password, new_password, confirm_password = request.form.get('current_password'), request.form.get(
            'new_password'), request.form.get('confirm_password')
        user = User.query.get(session['user_id'])
        if not check_password_hash(user.password_hash, current_password):
            flash('当前密码不正确！', 'danger')
        elif new_password != confirm_password:
            flash('两次输入的新密码不一致！', 'danger')
        else:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('密码修改成功！', 'success')
            return redirect(url_for('dashboard'))
        return redirect(url_for('change_password'))
    return render_template('change_password.html')


# ★★★ 用户中心逻辑大更新：增加未读消息数计算 ★★★
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('admin_logged_in'):
        return redirect(url_for('user_login'))

    user_submissions = Submission.query.filter_by(user_id=session['user_id']).order_by(
        Submission.timestamp.desc()).all()

    # 为每个案件计算未读消息数
    for sub in user_submissions:
        sub.unread_count = Comment.query.filter_by(submission_id=sub.id, read_by_user=False).count()

    return render_template('dashboard.html', submissions=user_submissions)


@app.route('/upload', methods=['POST'])
def upload_files():
    # ... (此函数无变化) ...
    if 'user_id' not in session or session.get('admin_logged_in'):
        return redirect(url_for('user_login'))
    description = request.form['description']
    uploaded_files = request.files.getlist('files')
    saved_filenames = []
    for file in uploaded_files:
        if file and file.filename != '':
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            original_filename = secure_filename(file.filename)
            saved_filename = f"{timestamp}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            file.save(filepath)
            saved_filenames.append(saved_filename)
    files_string = ";".join(saved_filenames)
    if not description or not (files_string or uploaded_files):
        flash('案件描述和文件均不能为空！', 'warning')
        return redirect(url_for('dashboard'))
    new_submission = Submission(description=description, files=files_string, user_id=session['user_id'])
    db.session.add(new_submission)
    db.session.commit()
    flash('您的新案件已成功提交！', 'success')
    return redirect(url_for('dashboard'))


# ★★★ 案件详情页逻辑大更新：增加标记为已读功能 ★★★
@app.route('/submission/<int:submission_id>')
def submission_detail(submission_id):
    is_admin, user_id = session.get('admin_logged_in'), session.get('user_id')
    if not is_admin and not user_id: return redirect(url_for('user_login'))

    submission = Submission.query.get_or_404(submission_id)
    if not is_admin and submission.user_id != user_id:
        flash('您无权访问此案件。', 'danger')
        return redirect(url_for('dashboard'))

    # 核心逻辑：进入页面时，将所有未读消息标记为已读
    if is_admin:
        Comment.query.filter_by(submission_id=submission.id, read_by_admin=False).update({'read_by_admin': True})
    else:
        Comment.query.filter_by(submission_id=submission.id, read_by_user=False).update({'read_by_user': True})
    db.session.commit()

    return render_template('submission_detail.html', submission=submission)


# ★★★ 留言提交逻辑大更新：设置初始已读状态 ★★★
@app.route('/submission/<int:submission_id>/comment', methods=['POST'])
def post_comment(submission_id):
    is_admin, user_id = session.get('admin_logged_in'), session.get('user_id')
    if not (is_admin or user_id): return redirect(url_for('user_login'))

    submission = Submission.query.get_or_404(submission_id)
    if not is_admin and submission.user_id != user_id:
        flash('您无权在此案件留言。', 'danger')
        return redirect(url_for('dashboard'))

    comment_text = request.form.get('comment_text')
    if comment_text:
        # 创建新留言，并根据发送者身份设置初始的已读状态
        if is_admin:
            # 客服发的，自己当然算已读，但用户不算
            new_comment = Comment(text=comment_text, user_id=user_id, submission_id=submission.id, read_by_admin=True,
                                  read_by_user=False)
        else:
            # 用户发的，自己算已读，但客服不算
            new_comment = Comment(text=comment_text, user_id=user_id, submission_id=submission.id, read_by_user=True,
                                  read_by_admin=False)

        db.session.add(new_comment)
        db.session.commit()
        flash('留言成功！', 'success')
    else:
        flash('留言内容不能为空！', 'warning')

    return redirect(url_for('submission_detail', submission_id=submission.id))


# ★★★ 后台主页逻辑大更新：增加未读消息数计算 ★★★
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))

    search_query, search_status = request.args.get('q', ''), request.args.get('status', '')
    page = request.args.get('page', 1, type=int)

    query = Submission.query.join(User).order_by(Submission.timestamp.desc())
    if search_query:
        search_term = f"%{search_query}%"
        query = query.filter(or_(User.username.like(search_term), Submission.description.like(search_term)))
    if search_status:
        query = query.filter(Submission.status == search_status)

    pagination = query.paginate(page=page, per_page=app.config['ITEMS_PER_PAGE'], error_out=False)
    submissions_on_page = pagination.items

    # 为当前页的每个案件计算未读消息数
    for sub in submissions_on_page:
        sub.unread_count = Comment.query.filter_by(submission_id=sub.id, read_by_admin=False).count()

    return render_template('admin.html',
                           submissions=submissions_on_page,
                           pagination=pagination,
                           status_options=STATUS_OPTIONS,
                           search_query=search_query,
                           search_status=search_status)


# ... (从 @app.route('/admin/login') 到文件结尾的所有路由代码保持不变) ...
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form['password'] == ADMIN_PASSWORD:
            session.clear()
            session['admin_logged_in'] = True
            admin_user = User.query.filter_by(username='admin_user').first()
            if not admin_user:
                admin_user = User(username='admin_user', password_hash=generate_password_hash(ADMIN_PASSWORD))
                db.session.add(admin_user)
                db.session.commit()
            session['user_id'] = admin_user.id
            session['username'] = admin_user.username
            flash('客服登录成功！', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('后台密码错误！', 'danger')
            return redirect(url_for('admin_login'))
    return render_template('login.html')


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    flash('客服已安全退出。', 'info')
    return redirect(url_for('admin_login'))


@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/upload_report/<int:submission_id>', methods=['POST'])
def upload_report(submission_id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    report_file, target_submission = request.files.get('report'), Submission.query.get(submission_id)
    if report_file and target_submission:
        timestamp, original_filename = datetime.datetime.now().strftime("%Y%m%d_%H%M%S"), secure_filename(
            report_file.filename)
        saved_filename = f"REPORT_{timestamp}_{original_filename}"
        report_file.save(os.path.join(app.config['UPLOAD_FOLDER'], saved_filename))
        target_submission.report_file = saved_filename
        target_submission.status = '已完成'
        db.session.commit()
        flash(f'案件ID {submission_id} 的报告上传成功！', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/update_status/<int:submission_id>', methods=['POST'])
def update_status(submission_id):
    if not session.get('admin_logged_in'): return redirect(url_for('admin_login'))
    submission, new_status = Submission.query.get_or_404(submission_id), request.form.get('status')
    if new_status in STATUS_OPTIONS:
        submission.status = new_status
        db.session.commit()
        flash(f'案件ID {submission.id} 的状态已更新为 "{new_status}"', 'success')
    else:
        flash('无效的状态值！', 'danger')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)