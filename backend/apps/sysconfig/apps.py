from __future__ import annotations

from django.apps import AppConfig


class SysconfigConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.sysconfig"
    verbose_name = "集成配置"

    def ready(self) -> None:
        from django.db.models.signals import post_delete, post_save
        from django.dispatch import receiver

        from apps.sysconfig.models import IntegrationSetting
        from apps.sysconfig.store import invalidate_config

        @receiver(post_save, sender=IntegrationSetting, weak=False)
        def _invalidate_on_save(sender: object, instance: object, **kwargs: object) -> None:
            del sender, kwargs
            key = str(getattr(instance, "key", "") or "")
            if key:
                invalidate_config(key)

        @receiver(post_delete, sender=IntegrationSetting, weak=False)
        def _invalidate_on_delete(sender: object, instance: object, **kwargs: object) -> None:
            del sender, kwargs
            key = str(getattr(instance, "key", "") or "")
            if key:
                invalidate_config(key)
