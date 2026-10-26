"""L0 · Operación del compose (N18): usuarios de Postgres, backups, mantenimiento, alertas,
/admin/ y resolución de nombres en nginx.

Se parsean los ficheros con `yaml.safe_load` y texto; ni se importa Django ni se levanta la pila
(en este entorno Docker Hub responde 429).

  AU-27  `web` ya no se conecta como superusuario ni recibe su contraseña: lee `backend/.env`,
         y el superusuario y el usuario de migraciones viven en `backend/.env.db`, que sólo
         leen `db`, `db-roles`, `migrate` y `backup`. `db-roles` aplica
         `infrastructure/postgres/apply-roles.sh` antes de `migrate`, y `web` espera a ambos.
         El exportador usa su propio usuario con `pg_monitor`.

  AU-17  `backup` hace un `pg_dump` diario a backend/backups/postgres y `maintenance`, cada
         día, purga tokens, sesiones, huérfanos y altas caducadas, y copia el bucket a
         backend/backups/minio. Las copias no entran en git ni en la imagen.

  AU-18  Grafana avisa por correo (contact point `email` a ALERT_EMAIL, por el mismo SMTP que el
         registro) de cuatro reglas: un target caído, 5xx, 503 de controles que fallan
         cerrados y una ráfaga de 429. Las reglas usan métricas que la pila exporta.

  AU-22  /admin/ sólo se monta con DJANGO_ADMIN_ENABLED=true (por defecto no), y nginx le
         aplica el límite del login.
  AU-26  nginx resuelve `web` con el DNS de Docker en cada petición (resolver + variable en
         `proxy_pass`), en vez de una vez al arrancar: recrear `web` con otra IP ya no da 502.

El comportamiento contra servicios de verdad lo prueban, en L1, `test_roles_postgres.py`,
`test_backups.py`, `test_backup_minio.py` y `test_mantenimiento.py`.
"""

import importlib.util
import re

import pytest
import yaml

pytestmark = pytest.mark.l0

_COMPOSE = "backend/docker-compose.yml"
_ENV_DB_LECTORES = {"db", "db-roles", "migrate", "backup"}


@pytest.fixture(scope="module")
def compose_text(read_repo_text):
    return read_repo_text(_COMPOSE)


@pytest.fixture(scope="module")
def servicios(compose_text):
    return yaml.safe_load(compose_text)["services"]


def _env_files(svc):
    ef = svc.get("env_file") or []
    return [ef] if isinstance(ef, str) else [e if isinstance(e, str) else e["path"] for e in ef]


def _texto(svc, clave):
    valor = svc.get(clave)
    if valor is None:
        return ""
    if isinstance(valor, list):
        return " ".join(map(str, valor))
    if isinstance(valor, dict):
        return yaml.safe_dump(valor, width=10_000)
    return str(valor)


def _env_example(read_repo_text, rel):
    claves = {}
    for linea in read_repo_text(rel).splitlines():
        m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", linea.strip())
        if m:
            claves[m.group(1)] = m.group(2)
    return claves


# =========================================================================== #
# AU-27 — usuarios de Postgres
# =========================================================================== #
def test_n18_solo_los_servicios_de_bd_leen_env_db(servicios):
    lectores = {n for n, s in servicios.items() if ".env.db" in _env_files(s)}
    assert lectores == _ENV_DB_LECTORES, (
        f"leen backend/.env.db: {sorted(lectores)}; deben ser sólo {sorted(_ENV_DB_LECTORES)}"
    )
    assert _env_files(servicios["web"]) == [".env"]


def test_n18_ningun_servicio_interpola_el_superusuario(compose_text):
    """Compose interpola `${VAR}` desde backend/.env: si el compose citara POSTGRES_PASSWORD o
    DB_MIGRATE_PASSWORD, tendrían que estar en el .env que lee `web`."""
    for var in ("POSTGRES_USER", "POSTGRES_PASSWORD", "DB_MIGRATE_USER", "DB_MIGRATE_PASSWORD"):
        assert f"${{{var}" not in compose_text, f"el compose interpola {var}"


def test_n18_db_roles_y_migrate_antes_que_web(servicios):
    roles = servicios["db-roles"]
    assert roles["image"] == servicios["db"]["image"], "db-roles debe usar la imagen de db (psql)"
    assert "apply-roles.sh" in _texto(roles, "command")
    assert roles["depends_on"]["db"]["condition"] == "service_healthy"
    assert str(roles.get("restart", "no")) == "no"

    migrate = servicios["migrate"]
    comando = _texto(migrate, "command")
    assert "manage.py migrate" in comando and "DB_MIGRATE_USER" in comando
    assert migrate["depends_on"]["db-roles"]["condition"] == "service_completed_successfully"

    web = servicios["web"]
    assert "manage.py migrate" not in _texto(web, "command"), "web no debe migrar: no tiene DDL"
    assert web["depends_on"]["migrate"]["condition"] == "service_completed_successfully"


def test_n18_el_exportador_usa_su_usuario(servicios):
    env = servicios["postgres-exporter"]["environment"]
    assert env["DATA_SOURCE_USER"] == "${DB_MONITOR_USER:?falta DB_MONITOR_USER en backend/.env}"
    assert env["DATA_SOURCE_PASS"] == (
        "${DB_MONITOR_PASSWORD:?falta DB_MONITOR_PASSWORD en backend/.env}"
    )


def test_n18_plantillas_separan_los_secretos_de_bd(read_repo_text):
    env = _env_example(read_repo_text, "backend/.env.example")
    env_db = _env_example(read_repo_text, "backend/.env.db.example")
    for clave in ("DB_USER", "DB_PASSWORD", "DB_MONITOR_USER", "DB_MONITOR_PASSWORD"):
        assert clave in env, f"falta {clave} en backend/.env.example"
    for clave in ("POSTGRES_USER", "POSTGRES_PASSWORD", "DB_MIGRATE_USER", "DB_MIGRATE_PASSWORD"):
        assert clave in env_db, f"falta {clave} en backend/.env.db.example"
        assert clave not in env, f"{clave} no puede ir en backend/.env: lo lee `web`"
    for clave, valor in {**env, **env_db}.items():
        if clave.endswith("PASSWORD"):
            assert valor == "", f"{clave} lleva un valor en la plantilla"


def test_n18_env_db_ignorado_y_plantilla_versionada(read_repo_text):
    gitignore = read_repo_text(".gitignore")
    assert ".env*" in gitignore.splitlines()
    assert "!.env.db.example" in gitignore.splitlines()


# =========================================================================== #
# AU-17 — copias y mantenimiento
# =========================================================================== #
def test_n18_servicio_backup(servicios):
    backup = servicios["backup"]
    assert backup["image"] == servicios["db"]["image"], "backup usa la imagen de db (pg_dump)"
    assert "backup.sh" in _texto(backup, "command")
    assert "./backups/postgres:/backups" in backup["volumes"]
    assert backup["restart"] == "unless-stopped"


def test_n18_servicio_maintenance(servicios):
    m = servicios["maintenance"]
    assert m["build"] == "."
    assert _env_files(m) == [".env"], "maintenance sólo necesita el usuario de la app"
    assert "infrastructure/maintenance/maintenance.sh" in _texto(m, "command")
    assert "./backups/minio:/backups/minio" in m["volumes"]
    assert m["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
    assert m["depends_on"]["minio"]["condition"] == "service_healthy"
    assert m["restart"] == "unless-stopped"


def test_n18_el_mantenimiento_lo_hace_todo_y_no_se_para(read_repo_text):
    script = read_repo_text("backend/infrastructure/maintenance/maintenance.sh")
    for paso in ("flushexpiredtokens", "clearsessions", "cleanup_orphans",
                 "purge_pending_registrations", "backup_minio"):
        assert f"run {paso}" in script, f"maintenance.sh no ejecuta {paso}"
    assert 'python manage.py "$@"' in script
    assert "while true" in script and "sleep" in script
    ordenes = [ln.strip() for ln in script.splitlines() if not ln.strip().startswith("#")]
    assert not any(ln.startswith("set -e") for ln in ordenes), (
        "un paso que falla no debe parar los demás ni el bucle"
    )


def test_n18_las_copias_no_van_a_git_ni_a_la_imagen(read_repo_text):
    assert "backend/backups/" in read_repo_text(".gitignore").splitlines()
    assert "backups/" in read_repo_text("backend/.dockerignore").splitlines()


def test_n18_app_puede_escribir_la_copia_de_minio(read_repo_text):
    """`maintenance` baja a `app` en el entrypoint; el bind mount lo crea Docker como root."""
    entrypoint = read_repo_text("backend/docker-entrypoint.sh")
    assert "/backups/minio" in entrypoint and "chown" in entrypoint


# =========================================================================== #
# AU-18 — alertas por correo
# =========================================================================== #
_ALERTAS = "backend/infrastructure/monitoring/grafana/provisioning/alerting/alertas.yml"


@pytest.fixture(scope="module")
def alertas(read_repo_text):
    return yaml.safe_load(read_repo_text(_ALERTAS))


@pytest.fixture(scope="module")
def metric_names(repo_path):
    path = repo_path("backend/infrastructure/monitoring/check_dashboard_metrics.py")
    spec = importlib.util.spec_from_file_location("check_dashboard_metrics", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.metric_names


def test_n18_grafana_monta_las_alertas_y_tiene_smtp(servicios):
    g = servicios["grafana"]
    montajes = {v.split(":")[1] for v in g["volumes"] if ":" in v}
    assert "/etc/grafana/provisioning/alerting" in montajes
    env = g["environment"]
    assert env["GF_SMTP_ENABLED"] == "true"
    assert env["GF_SMTP_HOST"] == "${DJANGO_EMAIL_HOST}:${DJANGO_EMAIL_PORT}"
    assert env["GF_SMTP_PASSWORD"] == "${DJANGO_EMAIL_HOST_PASSWORD}"
    assert env["GF_SMTP_FROM_ADDRESS"].startswith("${DJANGO_DEFAULT_FROM_EMAIL:?")
    assert env["ALERT_EMAIL"] == "${ALERT_EMAIL:?falta ALERT_EMAIL en backend/.env}"


def test_n18_contact_point_y_politica(alertas):
    (punto,) = alertas["contactPoints"]
    (receptor,) = punto["receivers"]
    assert receptor["type"] == "email"
    assert receptor["settings"]["addresses"] == "${ALERT_EMAIL}"
    (politica,) = alertas["policies"]
    assert politica["receiver"] == punto["name"]


def test_n18_reglas_bien_formadas(alertas, read_repo_text):
    ds = yaml.safe_load(read_repo_text(
        "backend/infrastructure/monitoring/grafana/provisioning/datasources/datasource.yml"
    ))["datasources"][0]
    assert ds.get("uid"), "la fuente de datos necesita uid para que las reglas la citen"

    reglas = [r for g in alertas["groups"] for r in g["rules"]]
    assert len(reglas) == 4
    assert len({r["uid"] for r in reglas}) == 4
    for r in reglas:
        refs = {d["refId"]: d for d in r["data"]}
        assert r["condition"] in refs, f"{r['title']}: la condición no es una consulta"
        consultas = [d for d in r["data"] if d["datasourceUid"] != "__expr__"]
        assert consultas and all(d["datasourceUid"] == ds["uid"] for d in consultas)
        for d in r["data"]:
            if d["datasourceUid"] == "__expr__":
                assert d["model"]["expression"] in refs, f"{r['title']}: expresión huérfana"
        assert re.fullmatch(r"\d+m", r["for"]), r["for"]
        assert r["labels"]["severity"] in {"critical", "warning"}
        assert r["annotations"]["summary"]


def test_n18_reglas_sobre_metricas_que_existen(alertas, metric_names, read_repo_text):
    """`up` lo genera Prometheus para cada target; la de Django es la misma que pinta el
    dashboard, que L2 comprueba contra la pila (N6)."""
    exportadas = {"up", "django_http_responses_total_by_status_view_method_total"}
    for g in alertas["groups"]:
        for r in g["rules"]:
            for d in r["data"]:
                if d["datasourceUid"] != "__expr__":
                    assert metric_names(d["model"]["expr"]) <= exportadas, d["model"]["expr"]
    assert "django_http_responses_total_by_status_view_method_total" in read_repo_text(
        "backend/infrastructure/monitoring/grafana/dashboards/backend-dashboard.json"
    )


def test_n18_alert_email_en_la_plantilla(read_repo_text):
    env = _env_example(read_repo_text, "backend/.env.example")
    assert "ALERT_EMAIL" in env
    # Grafana 10.1 rechaza el remitente `no-reply@localhost` y no arranca (comprobado con la
    # imagen fijada en el compose).
    remitente = env["DJANGO_DEFAULT_FROM_EMAIL"]
    assert re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", remitente), remitente


# =========================================================================== #
# AU-22 y AU-26 — /admin/ y resolución de `web` en nginx
# =========================================================================== #
@pytest.fixture(scope="module")
def nginx(read_repo_text):
    return read_repo_text("backend/infrastructure/nginx/nginx.conf")


def _sin_comentarios(texto):
    return "\n".join(ln.split("#", 1)[0] for ln in texto.splitlines())


def test_n18_admin_desactivado_por_defecto_en_settings(read_repo_text):
    settings = read_repo_text("backend/demo/settings.py")
    assert 'ADMIN_ENABLED = _env_bool("DJANGO_ADMIN_ENABLED", "false")' in settings
    urls = read_repo_text("backend/demo/urls.py")
    assert "settings.ADMIN_ENABLED" in urls


def test_n18_nginx_limita_admin(nginx):
    conf = _sin_comentarios(nginx)
    m = re.search(r"location\s+\^~\s+/admin/\s*\{([^}]*)\}", conf)
    assert m, "nginx no tiene un location propio para /admin/"
    assert re.search(r"limit_req\s+zone=auth_zone", m.group(1))


def test_n18_nginx_resuelve_web_en_cada_peticion(nginx):
    conf = _sin_comentarios(nginx)
    assert re.search(r"resolver\s+127\.0\.0\.11\b[^;]*valid=\d+s", conf), (
        "falta `resolver 127.0.0.11 valid=…` (DNS de Docker)"
    )
    assert "upstream backend_django" not in conf, (
        "un bloque upstream se resuelve una sola vez, al arrancar nginx"
    )
    destinos = re.findall(r"proxy_pass\s+([^;]+);", conf)
    assert destinos and all(d.strip() == "$django_upstream" for d in destinos), destinos
    assert re.search(r"set\s+\$django_upstream\s+http://web:8000;", conf)
