# Material TLS de nginx

`nginx.conf` espera aquí dos ficheros, **ninguno de los cuales está en git**
(`.gitignore`: `backend/infrastructure/nginx/ssl/*.pem`):

| Fichero | Contenido |
|---|---|
| `fullchain.pem` | Certificado del servidor, seguido de la cadena intermedia |
| `privkey.pem` | Clave privada, sin contraseña (nginx arranca desatendido) |

Sin ellos nginx **no arranca**: falla con `cannot load certificate`.

## Desarrollo — certificado autofirmado

No hay dominio ni CA, así que en local sólo cabe autofirmar. El navegador
mostrará un aviso de certificado no fiable en la primera visita; es esperado.

```bash
cd backend/infrastructure/nginx/ssl

openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout privkey.pem -out fullchain.pem \
  -subj "/C=ES/O=Gestor de Contrasenas (dev)/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:web,IP:127.0.0.1" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

chmod 600 privkey.pem
```

En Git Bash sobre Windows hay que anteponer `MSYS_NO_PATHCONV=1`, o el `-subj`
se convierte en una ruta de Windows y `openssl` lo rechaza.

## Producción — certificado real

Sustituir ambos ficheros por los de una CA pública (Let's Encrypt con `certbot`,
o el proveedor que corresponda) conservando los mismos nombres. Nada más cambia:
`nginx.conf` no los referencia por otro sitio.

> ⚠️ **HSTS.** `nginx.conf` envía `Strict-Transport-Security` con `max-age` de un
> año e `includeSubDomains`. Una vez que un navegador lo ha visto, se niega a
> hablar en texto plano con ese host hasta que expire, **aunque se retire la
> cabecera**. Con un dominio real, no activar HSTS hasta tener el certificado
> definitivo funcionando.
