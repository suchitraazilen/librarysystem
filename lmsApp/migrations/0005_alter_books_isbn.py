# Generated by Django 4.0.6 on 2022-09-02 07:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lmsApp', '0004_rename_sub_category_books_category_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='books',
            name='isbn',
            field=models.IntegerField(max_length=250),
        ),
    ]
