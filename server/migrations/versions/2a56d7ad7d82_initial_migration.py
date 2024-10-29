"""Initial migration

Revision ID: 2a56d7ad7d82
Revises: 
Create Date: 2024-10-07 16:17:47.060475

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2a56d7ad7d82'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('aes_file', schema=None) as batch_op:
        batch_op.alter_column('filetype',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=255),
               existing_nullable=False)

    with op.batch_alter_table('des_file', schema=None) as batch_op:
        batch_op.alter_column('filetype',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=255),
               existing_nullable=False)

    with op.batch_alter_table('rc4_file', schema=None) as batch_op:
        batch_op.alter_column('filetype',
               existing_type=sa.VARCHAR(length=50),
               type_=sa.String(length=255),
               existing_nullable=False)

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('username',
               existing_type=sa.VARCHAR(length=150),
               type_=sa.String(length=255),
               existing_nullable=False)
        batch_op.alter_column('email',
               existing_type=sa.VARCHAR(length=150),
               type_=sa.String(length=255),
               existing_nullable=False)
        batch_op.alter_column('password',
               existing_type=sa.VARCHAR(length=150),
               type_=sa.String(length=255),
               existing_nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('password',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=150),
               existing_nullable=False)
        batch_op.alter_column('email',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=150),
               existing_nullable=False)
        batch_op.alter_column('username',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=150),
               existing_nullable=False)

    with op.batch_alter_table('rc4_file', schema=None) as batch_op:
        batch_op.alter_column('filetype',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=50),
               existing_nullable=False)

    with op.batch_alter_table('des_file', schema=None) as batch_op:
        batch_op.alter_column('filetype',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=50),
               existing_nullable=False)

    with op.batch_alter_table('aes_file', schema=None) as batch_op:
        batch_op.alter_column('filetype',
               existing_type=sa.String(length=255),
               type_=sa.VARCHAR(length=50),
               existing_nullable=False)

    # ### end Alembic commands ###
