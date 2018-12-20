#! /usr/bin/env python

from app import create_app,db
from app.models import User,Role,Permission,Post,LakerMessage,LakerNews,Comment,Follow
from flask_migrate import Migrate,MigrateCommand
from flask_script import Manager,Shell


app = create_app('development')
manager = Manager(app)
migrate = Migrate(app,db)


def make_shell_context():
    return dict(db=db, User=User, Role=Role,Permission=Permission,Post=Post,
                LakeMessage=LakerMessage,LakerNews=LakerNews,Comment=Comment,Follow=Follow)

manager.add_command("shell",Shell(make_context=make_shell_context))
manager.add_command('db',MigrateCommand)

if __name__ =="__main__":
    manager.run()