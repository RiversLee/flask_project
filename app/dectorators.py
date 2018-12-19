#unicoding=utf-8
from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission

#检查常规用户的权限
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_funciton(*args,**kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(args,kwargs)
        return decorated_funciton
    return decorator

#检查管理员权限的函数
def admin_required(f):
    return permission_required(Permission.ADMIN)(f)