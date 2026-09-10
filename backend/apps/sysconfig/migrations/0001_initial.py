from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies: list[str] = []

    operations: list[object] = [
        migrations.CreateModel(
            name="IntegrationSetting",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key", models.CharField(max_length=64, unique=True)),
                ("value", models.TextField(blank=True, default="")),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "集成配置",
                "verbose_name_plural": "集成配置",
                "db_table": "integration_setting",
            },
        ),
    ]
