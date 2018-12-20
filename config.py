import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_DATABASE_URI = 'mysql://root:12345678@127.0.0.1:3306/flaskblog'
    MAIL_SERVER = 'smtp.qq.com'
    MAIL_PORT = 465
    MAIL_USE_SSL = True
    MAIL_USE_TLS = False
    MAIL_USERNAME = '571970620@qq.com'
    MAIL_PASSWORD= 'bjcnlqfzblpmbfdd'
    MAIL_DEFAULT_SENDER = 'RiverBlog<571970620@qq.com>'
    FLASKY_MAIL_SUBJECT_PREFIX = '[River information]'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')
    FLASKY_MAIL_SENDER = 'RiverLee<571970620@qq.com>'
    FLASKY_POSTS_PER_PAGE = 10
    FLASKY_COMMENTS_PER_PAGE = 30
    FLASKY_FOLLOWERS_PER_PAGE = 50
    @staticmethod
    def init_app(app):
        pass
class DevelopmentConfig(Config):
    Debug = True

config = {
    'development':DevelopmentConfig
}