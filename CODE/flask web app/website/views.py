from mailbox import Message
from flask import Blueprint, abort, flash, redirect, render_template, url_for
from flask_login import current_user, login_required, login_user, logout_user
from .admin import admin, RoleForm, UserAssignForm
from .auth import auth, RegistrationForm, LoginForm, PasswordResetRequestForm
from .supervisor import supervisor, TaskForm, TaskAssignForm, UpdateTaskForm
from .home import home
from .models import Role, User, Task, db
from .__init__ import db

views = Blueprint('views', __name__)


def check_admin():
    # prevent non-admins from accessing the page
    if not current_user.is_admin:
        abort(403)

def check_supervisor():
    # prevent non-supervisor from accessing the page
    if not current_user.is_supervisor:
        abort(403)


@admin.route('/roles', methods=['GET', 'POST'])
@login_required
def list_roles():
    check_admin()
    "List all roles"

    roles = Role.query.all()

    return render_template('admin/roles/roles.html', roles=roles, title="Roles")

@admin.route('/roles/add', methods=['GET', 'POST'])
@login_required
def add_role():
    check_admin()
    "Add a role to the database"
    add_role = True

    form = RoleForm()
    if form.validate_on_submit():
        role = Role(name=form.name.data, description=form.description.data)

        try:
            # add role to the database
            db.session.add(role)
            db.session.commit()
            flash('You have successfully added a new role.')
        except:
            # in case role name already exists
            flash('Error: role name already exists.')

        # redirect to the roles page
        return redirect(url_for('admin.list_roles'))

    # load role template
    return render_template('admin/roles/role.html', form=form, title="Add Role")

@admin.route('/roles/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_role(id):
    check_admin()
    "Edit a role"

    add_role = False

    role = Role.query.get_or_404(id)
    form = RoleForm(obj=role)
    if form.validate_on_submit():
        role.name = form.name.data
        role.description = form.description.data
        db.session.commit()
        flash('You have successfully edited the role.')

        # redirect to the roles page
        return redirect(url_for('admin.list_roles'))

    form.description.data = role.description
    form.name.data = role.name
    return render_template('admin/roles/role.html', add_role=add_role, form=form, title="Edit Role")

@admin.route('/roles/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_role(id):
    check_admin()
    "Delete a role from the database"

    role = Role.query.get_or_404(id)
    db.session.delete(role)
    db.session.commit()
    flash('You have successfully deleted the role.')

    # redirect to the roles page
    return redirect(url_for('admin.list_roles'))

@admin.route('/users')
@login_required
def list_users():
    check_admin()
    "List all users"

    check_admin()

    users = User.query.all()
    return render_template('admin/users/users.html', users=users, title="Users")

@admin.route('/users/assign/<int:id>', methods=['GET', 'POST'])
@login_required
def assign_user(id):
    check_admin()
    "Assign a role to an user"

    check_admin()

    user = User.query.get_or_404(id)

    # prevent admin from being assigned a role
    if user.is_admin:
        abort(403)

    form = UserAssignForm(obj=user)
    if form.validate_on_submit():
        user.role = form.role.data
        db.session.add(user)
        db.session.commit()
        flash('You have successfully assigned a role.')

        # redirect to the roles page
        return redirect(url_for('admin.list_users'))

    return render_template('admin/users/user.html', user=user, form=form, title="Assign User")

@admin.route('/users/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_user(id):
    check_admin()
    "Delete a user from the database"

    check_admin()

    user = User.query.get_or_404(id)

    # prevent admin from being deleted
    if user.is_admin:
        abort(403)
    db.session.delete(user)
    db.session.commit()
    flash('You have successfully deleted the user.')

    # redirect to the roles page
    return redirect(url_for('admin.list_users'))

@auth.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    '''Handle requests to the /register route'''

    form = RegistrationForm()

    if form.validate_on_submit():
            user = User(email=form.email.data,
                        first_name=form.first_name.data,
                        last_name=form.last_name.data,
                        staffNO=form.staffNO.data,
                        rank=form.rank.data,
                        password=form.password.data)
            # add user to the database
            db.session.add(user)
            db.session.commit()
            flash('You have successfully registered! You may now login.')

            # redirect to the login page
            return redirect(url_for('auth.login'))

    # load registration template    
    return render_template("auth/sign_up.html", form=form, title="Register" )

@auth.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle requests to the /login route
    Log a user in through the login form
    """
    form = LoginForm()
    if form.validate_on_submit():

        # check whether user exists in the database and whether
        # the password entered matches the password in the database
        user = User.query.filter_by(email=form.login_id.data).first()
        if user is not None and user.verify_password(form.password.data):
            # log user in
            login_user(user, remember=True)

            # redirect to the appropriate dashboard page after login
            if user.is_admin:
                return redirect(url_for('home.admin_dashboard'))
            elif user.is_supervisor:
                return redirect(url_for('home.supervisor_dashboard'))
            else:
                return redirect(url_for('home.dashboard'))

        else:
            flash('Invalid email or password.')
            # increment the failed login attempts counter
            user.failed_login_attempts += 1
            db.session.commit()

            # check if the user has reached the maximum failed login attempts
            if user.failed_login_attempts >= 3:
                # render the login template with the reset password button
               show_reset_password = True
    return render_template("auth/login.html", form=form, title='Login')
        
@auth.route('/logout')
@login_required
def logout():
    """
    Handle requests to the /logout route
    Log a user out through the logout link
    """
    logout_user()
    flash('You have successfully been logged out.')

    # redirect to the login page
    return redirect(url_for('auth.login'))

@auth.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    """
    Handle requests to the /reset-password route
    Reset a user's password through the reset password form
    """
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            user.password = form.password.data
            db.session.commit()
            flash('You have successfully reset your password. You may now login.')

            # redirect to the login page
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid email.')

    # load reset password template
    return render_template('auth/reset_password.html', form=form, title='Reset Password')


@supervisor.route('/tasks', methods=['GET', 'POST'])
@login_required
def create_task():
    check_supervisor()
    "Create a task"
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(title=form.title.data,
                    description=form.description.data,
                    priority=form.priority.data,
                    assignee=form.assignee.data)
        db.session.add(task)
        db.session.commit()
        flash('You have successfully added a new task.')
        return redirect(url_for('supervisor.create_task'))
    return render_template('supervisor/tasks/task.html', form=form, title="Create Task")

@supervisor.route('/tasks/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def assign_task():
    check_supervisor()
    "Assign a task to a user"
    form = TaskAssignForm()
    users = User.query.filter_by(is_admin=False, is_supervisor=False).all()
    form.assignees.choices = [(user.id, user.username) for user in users]
    if form.validate_on_submit():
        task_id = form.task_id.data
        task = Task.query.get(task_id)
        if task is None:
            flash('Invalid task ID.')
            return redirect(url_for('supervisor.list_tasks'))
        for assignee_id in form.assignees.data:
            user = User.query.get(assignee_id)
            if user is None:
                flash(f'Invalid user ID: {assignee_id}.')
                continue  # skip this assignee and continue with the next one
            task.assignee = user
            db.session.add(task)
        db.session.commit()
        flash('Task assigned successfully.')
        return redirect(url_for('supervisor.list_tasks'))
    return render_template('supervisor/tasks/assign_task.html', form=form, title="Assign Task")

@supervisor.route('/tasks/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def update_task(id):
    check_supervisor()
    "Edit a task"
    task = Task.query.get_or_404(id)
    form = UpdateTaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.priority = form.priority.data
        task.assignee = form.assignee.data
        db.session.commit()
        flash('You have successfully updated the task.')
        return redirect(url_for('supervisor.list_tasks'))
    form.title.data = task.title
    form.description.data = task.description
    form.priority.data = task.priority
    form.assignee.data = task.assignee
    return render_template('supervisor/tasks/task.html', form=form, title="Edit Task")

@supervisor.route('/tasks', methods=['GET', 'POST'])
@login_required
def list_tasks():
    check_supervisor()
    "List all tasks"
    tasks = Task.query.all()
    return render_template('supervisor/tasks/tasks.html', tasks=tasks, title="Tasks")

@supervisor.route('/tasks/<int:id>', methods=['GET', 'POST'])
@login_required
def search_task(id):
    check_supervisor()
    "Search for a task"
    task = Task.query.get_or_404(id)
    return render_template('supervisor/tasks/task.html', task=task, title="Task")

@supervisor.route('/tasks/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_task(id):
    check_supervisor()
    "Delete a task from the database"
    task = Task.query.get_or_404(id)
    db.session.delete(task)
    db.session.commit()
    flash('You have successfully deleted the task.')
    return redirect(url_for('supervisor.list_tasks'))


@home.route('/')
def homepage():
    """
    Render the homepage template on the / route
    """
    return render_template('home/index.html', title="Welcome")

@home.route('/dashboard')
@login_required
def dashboard():
    """
    Render the dashboard template on the /dashboard route
    """
    return render_template('home/dashboard.html', title="Dashboard")

@home.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """
    Render the admin dashboard template on the /admin/dashboard route
    """
    # prevent non-admins from accessing the page
    if not current_user.is_admin:
        abort(403)

    return render_template('home/admin_dashboard.html', title="Admin Dashboard")

@home.route('/supervisor/dashboard')
@login_required
def supervisor_dashboard():
    """
    Render the supervisor dashboard template on the /supervisor/dashboard route
    """
    # prevent non-supervisors from accessing the page
    if not current_user.is_supervisor:
        abort(403)

    return render_template('home/supervisor_dashboard.html', title="Supervisor Dashboard")

@home.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """
    Render the employee dashboard template on the /employee/dashboard route
    """

    return render_template('home/profilepage.html', title="User Profile")