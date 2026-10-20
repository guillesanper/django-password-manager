"""
L0 · settings.py sin ajustes muertos  —  N7 (§7·decies de AUDITORIA-SEGURIDAD.md)

Un ajuste que nadie lee es peor que no tenerlo: quien revisa settings.py cree que
existe un control (un bloqueo tras N fallos con su duración) que
no existe. Y una ruta punteada a un módulo inexistente no avisa hasta el día en que
alguien la usa.

  - Toda cadena `myapp.<módulo>.<Nombre>` de settings.py apunta a un fichero que
    existe y define ese nombre. `SIMPLE_JWT['TOKEN_OBTAIN_SERIALIZER']` apuntaba a
    `myapp.serializers.CustomTokenObtainPairSerializer`, y `myapp/serializers.py` no
    existe.
  - Los ajustes retirados por muertos no vuelven a asignarse. Por AST (trampa 16):
    que el nombre aparezca en un comentario no cuenta.
"""

import ast
import re

import pytest

pytestmark = pytest.mark.l0

# Ajustes del proyecto que no leía ningún código (ni de la app ni de una librería).
# Los valores reales de los bloqueos viven junto al código que los aplica: el del
# login en auth_views.py y el de la maestra en utils/master_key_guard.py.
_MUERTOS = (
    "MAX_FAILED_LOGIN_ATTEMPTS",
    "LOCKOUT_DURATION_MINUTES",
)

_RUTA_MYAPP = re.compile(r"myapp(\.\w+)+")


def _definidos(tree: ast.Module) -> set:
    nombres = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            nombres.add(node.name)
        elif isinstance(node, ast.Assign):
            nombres.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return nombres


def test_n7_rutas_myapp_de_settings_existen(settings_tree, repo_path):
    rutas = sorted({
        node.value
        for node in ast.walk(settings_tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and _RUTA_MYAPP.fullmatch(node.value)
    })
    assert rutas, "no se encontró ninguna ruta myapp.* en settings.py"

    rotas = []
    for ruta in rutas:
        modulo, nombre = ruta.rsplit(".", 1)
        fichero = repo_path("backend/" + modulo.replace(".", "/") + ".py")
        if not fichero.is_file():
            rotas.append(f"{ruta}: no existe {fichero.name}")
        elif nombre not in _definidos(ast.parse(fichero.read_text(encoding="utf-8"))):
            rotas.append(f"{ruta}: {fichero.name} no define {nombre}")
    assert not rotas, f"rutas de settings.py que no resuelven: {rotas}"


@pytest.mark.parametrize("nombre", _MUERTOS)
def test_n7_ajuste_muerto_no_asignado(settings_assignments, nombre):
    names, _ = settings_assignments
    assert nombre not in names, (
        f"{nombre} vuelve a estar en settings.py y ningún código lo lee: aparenta un "
        "control que no existe."
    )
