from app.db.schema import RoleName


def test_users_collection_disables_post_even_for_authenticated_users(
    client, auth_headers
):
    headers = auth_headers()

    response = client.post(
        "/api/v1/users",
        json={"name": "Test User"},
        headers=headers,
    )
    assert response.status_code == 405
    assert response.json() == {"detail": "Método no permitido"}


def test_user_endpoints_require_bearer_token(client):
    response = client.get("/api/v1/users")

    assert response.status_code == 401
    assert response.json() == {"detail": "Credenciales de autenticación inválidas"}


def test_admin_and_supervisor_can_list_users_but_agent_cannot(client, user_factory):
    admin = user_factory(role_name=RoleName.ADMIN)
    supervisor = user_factory(role_name=RoleName.SUPERVISOR)
    agent = user_factory(role_name=RoleName.AGENTE)

    admin_response = client.get("/api/v1/users", headers=admin["headers"])
    supervisor_response = client.get("/api/v1/users", headers=supervisor["headers"])
    agent_response = client.get("/api/v1/users", headers=agent["headers"])

    assert admin_response.status_code == 200
    assert supervisor_response.status_code == 200
    assert agent_response.status_code == 403
    assert agent_response.json() == {
        "detail": "No autorizado para realizar esta acción"
    }


def test_agent_can_view_only_own_user_while_admin_and_supervisor_can_view_any(
    client, user_factory
):
    target = user_factory(role_name=RoleName.AGENTE, name="Target User")
    admin = user_factory(role_name=RoleName.ADMIN)
    supervisor = user_factory(role_name=RoleName.SUPERVISOR)
    agent = user_factory(role_name=RoleName.AGENTE)

    admin_response = client.get(
        f"/api/v1/users/{target['id']}", headers=admin["headers"]
    )
    supervisor_response = client.get(
        f"/api/v1/users/{target['id']}", headers=supervisor["headers"]
    )
    own_response = client.get(f"/api/v1/users/{agent['id']}", headers=agent["headers"])
    forbidden_response = client.get(
        f"/api/v1/users/{target['id']}", headers=agent["headers"]
    )

    assert admin_response.status_code == 200
    assert supervisor_response.status_code == 200
    assert own_response.status_code == 200
    assert own_response.json()["id"] == agent["id"]
    assert forbidden_response.status_code == 403
    assert forbidden_response.json() == {
        "detail": "No autorizado para realizar esta acción"
    }


def test_agent_can_update_only_self_while_admin_and_supervisor_can_update_any(
    client, user_factory
):
    target = user_factory(role_name=RoleName.AGENTE, name="Before Target")
    admin = user_factory(role_name=RoleName.ADMIN)
    supervisor = user_factory(role_name=RoleName.SUPERVISOR)
    agent = user_factory(role_name=RoleName.AGENTE, name="Before Self")

    admin_response = client.put(
        f"/api/v1/users/{target['id']}",
        json={"name": "Updated by admin"},
        headers=admin["headers"],
    )
    supervisor_response = client.put(
        f"/api/v1/users/{target['id']}",
        json={"name": "Updated by supervisor"},
        headers=supervisor["headers"],
    )
    own_response = client.put(
        f"/api/v1/users/{agent['id']}",
        json={"name": "Updated self"},
        headers=agent["headers"],
    )
    forbidden_response = client.put(
        f"/api/v1/users/{target['id']}",
        json={"name": "Should fail"},
        headers=agent["headers"],
    )

    assert admin_response.status_code == 200
    assert admin_response.json()["name"] == "Updated by admin"
    assert supervisor_response.status_code == 200
    assert supervisor_response.json()["name"] == "Updated by supervisor"
    assert own_response.status_code == 200
    assert own_response.json()["id"] == agent["id"]
    assert own_response.json()["name"] == "Updated self"
    assert forbidden_response.status_code == 403
    assert forbidden_response.json() == {
        "detail": "No autorizado para realizar esta acción"
    }


def test_only_admin_can_delete_users(client, user_factory):
    admin = user_factory(role_name=RoleName.ADMIN)
    target_for_admin = user_factory(role_name=RoleName.AGENTE)
    supervisor = user_factory(role_name=RoleName.SUPERVISOR)
    target_for_supervisor = user_factory(role_name=RoleName.AGENTE)
    agent = user_factory(role_name=RoleName.AGENTE)
    target_for_agent = user_factory(role_name=RoleName.AGENTE)

    admin_response = client.delete(
        f"/api/v1/users/{target_for_admin['id']}", headers=admin["headers"]
    )
    supervisor_response = client.delete(
        f"/api/v1/users/{target_for_supervisor['id']}", headers=supervisor["headers"]
    )
    agent_response = client.delete(
        f"/api/v1/users/{target_for_agent['id']}", headers=agent["headers"]
    )

    assert admin_response.status_code == 200
    assert admin_response.json() == {"success": True}
    assert supervisor_response.status_code == 403
    assert supervisor_response.json() == {
        "detail": "No autorizado para realizar esta acción"
    }
    assert agent_response.status_code == 403
    assert agent_response.json() == {
        "detail": "No autorizado para realizar esta acción"
    }


def test_delete_user_returns_409_when_deleting_last_admin(client, user_factory):
    admin = user_factory(role_name=RoleName.ADMIN)

    response = client.delete(f"/api/v1/users/{admin['id']}", headers=admin["headers"])

    assert response.status_code == 409
    assert response.json() == {
        "detail": "No se puede eliminar al último ADMIN del sistema"
    }


def test_delete_user_allows_deleting_admin_when_another_admin_exists(
    client, user_factory
):
    acting_admin = user_factory(role_name=RoleName.ADMIN)
    target_admin = user_factory(role_name=RoleName.ADMIN)

    response = client.delete(
        f"/api/v1/users/{target_admin['id']}", headers=acting_admin["headers"]
    )

    assert response.status_code == 200
    assert response.json() == {"success": True}


def test_admin_can_update_user_role(client, user_factory):
    admin = user_factory(role_name=RoleName.ADMIN)
    target = user_factory(role_name=RoleName.AGENTE)

    response = client.patch(
        f"/api/v1/users/{target['id']}/role",
        json={"role": RoleName.SUPERVISOR},
        headers=admin["headers"],
    )

    assert response.status_code == 200
    assert response.json()["id"] == target["id"]
    assert response.json()["role"]["name"] == RoleName.SUPERVISOR


def test_update_user_role_returns_409_when_demoting_last_admin(client, user_factory):
    admin = user_factory(role_name=RoleName.ADMIN)

    response = client.patch(
        f"/api/v1/users/{admin['id']}/role",
        json={"role": RoleName.SUPERVISOR},
        headers=admin["headers"],
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "No se puede cambiar el rol del último ADMIN del sistema"
    }


def test_update_user_role_allows_demoting_admin_when_another_admin_exists(
    client, user_factory
):
    acting_admin = user_factory(role_name=RoleName.ADMIN)
    target_admin = user_factory(role_name=RoleName.ADMIN)

    response = client.patch(
        f"/api/v1/users/{target_admin['id']}/role",
        json={"role": RoleName.SUPERVISOR},
        headers=acting_admin["headers"],
    )

    assert response.status_code == 200
    assert response.json()["id"] == target_admin["id"]
    assert response.json()["role"]["name"] == RoleName.SUPERVISOR


def test_non_admin_cannot_update_user_role(client, user_factory):
    supervisor = user_factory(role_name=RoleName.SUPERVISOR)
    target = user_factory(role_name=RoleName.AGENTE)

    response = client.patch(
        f"/api/v1/users/{target['id']}/role",
        json={"role": RoleName.ADMIN},
        headers=supervisor["headers"],
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "No autorizado para realizar esta acción"}


def test_update_user_role_returns_404_when_user_does_not_exist(client, user_factory):
    admin = user_factory(role_name=RoleName.ADMIN)

    response = client.patch(
        "/api/v1/users/999999/role",
        json={"role": RoleName.ADMIN},
        headers=admin["headers"],
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Usuario no encontrado"}


def test_update_user_role_returns_422_for_invalid_role(client, user_factory):
    admin = user_factory(role_name=RoleName.ADMIN)
    target = user_factory(role_name=RoleName.AGENTE)

    response = client.patch(
        f"/api/v1/users/{target['id']}/role",
        json={"role": "INVALIDO"},
        headers=admin["headers"],
    )

    assert response.status_code == 422
