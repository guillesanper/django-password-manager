-- Usuarios de la aplicación (N18, AU-27). Lo ejecuta apply-roles.sh con el superusuario.
-- Idempotente: se puede aplicar en cada arranque.

-- 1. Los tres usuarios, sin privilegios de administración. Sólo el de migraciones puede crear
--    bases, para que L1 cree su base de test.
SELECT format('CREATE ROLE %I', :'migrate_user')
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'migrate_user') \gexec
SELECT format('CREATE ROLE %I', :'app_user')
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'app_user') \gexec
SELECT format('CREATE ROLE %I', :'monitor_user')
 WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'monitor_user') \gexec

ALTER ROLE :"migrate_user" WITH LOGIN NOSUPERUSER CREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'migrate_password';
ALTER ROLE :"app_user" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';
ALTER ROLE :"monitor_user" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'monitor_password';
GRANT pg_monitor TO :"monitor_user";

-- 2. El esquema es del usuario de migraciones, y nadie más crea objetos en él.
ALTER SCHEMA public OWNER TO :"migrate_user";
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- 3. Lo creado antes de N18 era del superusuario: pasa al de migraciones. Primero las tablas
--    (con ellas cambian sus secuencias de serial/identity) y después las secuencias sueltas.
SELECT format('ALTER TABLE public.%I OWNER TO %I', c.relname, :'migrate_user')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
   AND pg_get_userbyid(c.relowner) <> :'migrate_user' \gexec
SELECT format('ALTER SEQUENCE public.%I OWNER TO %I', c.relname, :'migrate_user')
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'S'
   AND pg_get_userbyid(c.relowner) <> :'migrate_user'
   AND NOT EXISTS (SELECT FROM pg_depend d
                    WHERE d.objid = c.oid AND d.deptype IN ('a', 'i')) \gexec

-- 4. La aplicación lee y escribe filas: ni DDL, ni TRUNCATE, ni referencias nuevas. Lo que
--    cree después `migrate` le llega por los privilegios por defecto.
GRANT CONNECT ON DATABASE :"db" TO :"app_user", :"monitor_user";
GRANT USAGE ON SCHEMA public TO :"app_user";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"app_user";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO :"app_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrate_user" IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"app_user";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migrate_user" IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO :"app_user";
