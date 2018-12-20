"""empty message

Revision ID: 62710847ba17
Revises: e47ba93893b6
Create Date: 2018-12-20 01:14:24.238914

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '62710847ba17'
down_revision = 'e47ba93893b6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('comments', sa.Column('lakenews_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'comments', 'news', ['lakenews_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'comments', type_='foreignkey')
    op.drop_column('comments', 'lakenews_id')
    # ### end Alembic commands ###