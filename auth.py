"""
Autenticación y control de acceso por rol — VOXDEI
---------------------------------------------------
IMPORTANTE (léelo antes de desplegar esto en serio):

Los usuarios de abajo (USERS) están hardcodeados en el código fuente
solo para poder probar HOY el control de acceso por rol en las 3
vistas (SuperAdmin / Admin / Operador). Esto es un placeholder, no
un sistema de identidad real. Antes de exponer VOXDEI fuera de tu
máquina de pruebas, esto debería reemplazarse por:
  - Usuarios reales en una base de datos (o el índice soc-annotations
    de OpenSearch, o Postgres) con contraseñas HASHEADAS (bcrypt/argon2),
    nunca en texto plano como aquí.
  - O, mejor aún para un SOC, un proveedor de identidad externo
    (LDAP/Active Directory u OIDC) si esto se integra a la red de
    una organización real.

La sesión sí es real (cookies de sesión firmadas por Flask con
app.secret_key) — lo que es una demo es de dónde salen las
contraseñas, no el mecanismo de sesión en sí.
"""

import os
from functools import wraps

from flask import redirect, request, session, url_for

# Jerarquía de roles: un rol superior puede hacer todo lo que puede
# hacer uno inferior. SuperAdmin ve/hace todo lo de Admin y Operador.
ROLE_LEVEL = {"Operador": 1, "Admin": 2, "SuperAdmin": 3}

# ---- PLACEHOLDER: reemplazar por un directorio de identidad real ----
USERS = {
    "operador":   {"password": os.environ.get("OPERADOR_PASSWORD", "operador123"),   "role": "Operador"},
    "admin":      {"password": os.environ.get("ADMIN_PASSWORD", "admin123"),         "role": "Admin"},
    "superadmin": {"password": os.environ.get("SUPERADMIN_PASSWORD", "superadmin123"), "role": "SuperAdmin"},
}


def check_login(username, password):
    """Devuelve el rol si las credenciales son válidas, None si no."""
    user = USERS.get(username)
    if user and user["password"] == password:
        return user["role"]
    return None


def current_role():
    return session.get("role")


def current_user():
    return session.get("username")


def role_at_least(min_role):
    """True si el rol de la sesión actual alcanza o supera min_role."""
    role = session.get("role")
    return ROLE_LEVEL.get(role, 0) >= ROLE_LEVEL.get(min_role, 999)


def require_role(min_role):
    """Decorador de ruta: exige sesión con rol >= min_role.
    Si no hay sesión o el rol no alcanza, redirige a /login."""
    min_level = ROLE_LEVEL[min_role]

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            role = session.get("role")
            if not role or ROLE_LEVEL.get(role, 0) < min_level:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped
    return decorator
