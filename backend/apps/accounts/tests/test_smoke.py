from __future__ import annotations

import pytest

from apps.accounts.models import Role, User


@pytest.mark.django_db
def test_create_user_smoke() -> None:
    user: User = User.objects.create_user(
        username="op1",
        password="scaffold-test-only",
        wecom_userid="op1",
        role=Role.OPERATOR,
    )
    assert User.objects.filter(wecom_userid="op1").exists()
    assert user.role == Role.OPERATOR
