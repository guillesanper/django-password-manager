"""Utilidades de petición compartidas.

`get_client_ip` es la ÚNICA implementación del proyecto (hallazgo A4). Antes
había diez copias —cinco en `middleware.py`, tres en `auth_views.py`, una en
`session_manager.py` y una en `logging_utils.py`— y todas hacían lo mismo:

    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()

Es decir, devolvían el primer valor de una cabecera que **escribe el cliente**.
Un atacante que rotase `X-Forwarded-For` en cada petición evadía el rate
limiting, el bloqueo de cuenta y el bloqueo por IP sospechosa, y además
envenenaba `SecurityEvent` y `ActivityLog`, que son la única evidencia forense.
Combinado con M12 permitía provocar el bloqueo de la IP de un tercero.

Modelo de confianza
-------------------
Sólo se mira `X-Forwarded-For` cuando el par TCP directo (`REMOTE_ADDR`) está en
`settings.TRUSTED_PROXIES`. Si la petición llega directa a gunicorn, la cabecera
es del cliente y se ignora por completo.

Dentro de la cadena no se toma el primer valor sino el que está a
`settings.TRUSTED_PROXY_HOPS` saltos del final, porque nginx usa
`$proxy_add_x_forwarded_for`: **añade** su `$remote_addr` a lo que trajera el
cliente. Así, con un único proxy, la cadena efectiva es

    [ …lo que el cliente inventase… , IP real vista por nginx , IP de nginx ]

y la única posición no falsificable es la penúltima. Contar desde la derecha es
lo que hace que el criterio de aceptación de la Fase 1 —repetir el ataque
variando `X-Forwarded-For` en cada petición y que siga cortando con 429— se
cumpla incluso cuando el cliente legítimo tiene una IP privada, como ocurre al
probar en local desde el host de Docker.

`TRUSTED_PROXIES` NO sirve para localizar al cliente dentro de la cadena, sólo
para decidir si la cadena es creíble; por eso su valor por defecto (los rangos
privados) puede ser amplio sin abrir un agujero.
"""

import ipaddress
import logging

from django.conf import settings

security_logger = logging.getLogger('security')

# Valor devuelto cuando no hay forma de determinar la IP (por ejemplo, peticiones
# sintéticas sin `REMOTE_ADDR`). Es una IP válida para `GenericIPAddressField`,
# así que nunca rompe el guardado de SecurityEvent/ActivityLog, y no se confunde
# con un cliente local real.
UNKNOWN_IP = '0.0.0.0'

# Vacío A PROPÓSITO: sin `settings.TRUSTED_PROXIES` no se cree a nadie y
# X-Forwarded-For se ignora por completo, de modo que la IP es siempre la del
# socket. Es el fallo seguro.
#
# Aquí vivía una copia de la lista de rangos privados. Como default era una
# trampa: si alguien borraba `TRUSTED_PROXIES` de settings, el sistema seguía
# funcionando sin dar ni un aviso y volvía a aceptar cadenas falsificadas desde
# cualquier dirección privada. Ahora la única lista está en settings.py
# (172.28.0.10/32, la IP fija de nginx) y este módulo no tiene opinión propia.
#
# El modo degradado es ruidoso, que es lo que se busca: todos los clientes
# aparecerían con la IP de nginx y los límites por IP empezarían a cortar de
# inmediato.
DEFAULT_TRUSTED_PROXIES = ()

_trusted_networks = None


def _get_trusted_networks():
    """Compila `settings.TRUSTED_PROXIES` una sola vez por proceso."""
    global _trusted_networks
    if _trusted_networks is None:
        entries = getattr(settings, 'TRUSTED_PROXIES', None) or DEFAULT_TRUSTED_PROXIES
        networks = []
        for entry in entries:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                security_logger.error(
                    "TRUSTED_PROXIES: entrada no válida ignorada: %r", entry
                )
        _trusted_networks = tuple(networks)
    return _trusted_networks


def _parse_ip(value):
    """Convierte un valor de cabecera en `ip_address`, o None si no es una IP.

    Acepta las formas con puerto que algunos proxies escriben (`1.2.3.4:5678`,
    `[::1]:5678`) porque un valor no reconocido se descarta, y descartar de más
    desplazaría la cadena.
    """
    if not value:
        return None

    value = value.strip()
    if value.startswith('[') and ']' in value:          # [::1]:5678
        value = value[1:value.index(']')]
    elif value.count(':') == 1 and '.' in value:        # 1.2.3.4:5678
        value = value.split(':', 1)[0]

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_trusted_proxy(ip):
    """¿Es `ip` (str o `ip_address`) un proxy en el que confiamos?"""
    if not isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip = _parse_ip(ip)
    if ip is None:
        return False
    return any(ip in network for network in _get_trusted_networks())


def get_client_ip_with_trust(request):
    """Devuelve `(ip, atribuible)` para el cliente de `request`.

    `atribuible` es True sólo cuando la IP devuelta NO puede haberla elegido el
    propio cliente. Se cumple en dos situaciones, y en ninguna más:

    - La conexión es directa (el par TCP no es un proxy de confianza): la IP es
      la del socket, y falsificarla exige falsificar el handshake TCP.
    - La conexión viene de un proxy de confianza Y la cadena
      `X-Forwarded-For` tiene al menos `TRUSTED_PROXY_HOPS + 1` entradas, es
      decir la posición que leemos la escribió nginx al hacer
      `$proxy_add_x_forwarded_for`, no el cliente.

    Cuando la cadena es más corta de lo esperado el índice se recorta a 0, y esa
    entrada sí la controla quien llama: la IP sigue sirviendo para registrar,
    pero **no** para bloquear a nadie (M12 + A4: es justo el camino por el que
    se podía provocar el bloqueo de la IP de un tercero).
    """
    remote_addr = _parse_ip(request.META.get('REMOTE_ADDR'))
    if remote_addr is None:
        return UNKNOWN_IP, False

    # Par TCP no reconocido como proxy: la petición no ha pasado por nginx, así
    # que X-Forwarded-For lo escribe quien nos habla y no vale nada.
    if not is_trusted_proxy(remote_addr):
        return str(remote_addr), True

    forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
    chain = [ip for ip in (_parse_ip(part) for part in forwarded.split(',')) if ip]
    if not chain:
        # Sin cabecera: nadie ha hecho de proxy, el par TCP es el cliente aunque
        # su IP sea privada. Es el caso del acceso directo a `web` en desarrollo.
        return str(remote_addr), True

    chain.append(remote_addr)

    hops = getattr(settings, 'TRUSTED_PROXY_HOPS', 1)
    index = len(chain) - 1 - hops

    if index < 0:
        # Menos entradas de las que deberían haber añadido los proxies: o falta
        # un `proxy_set_header X-Forwarded-For`, o TRUSTED_PROXY_HOPS es mayor
        # que el número real de saltos. Se queda con lo más a la izquierda que
        # hay, que es lo más cercano al cliente.
        security_logger.warning(
            "X-Forwarded-For más corta de lo esperado (%d entradas, %d saltos "
            "configurados) desde %s; revisa TRUSTED_PROXY_HOPS.",
            len(chain) - 1, hops, remote_addr,
        )
        return str(chain[0]), False

    return str(chain[index]), True


def get_client_ip(request):
    """Devuelve la IP del cliente. Siempre una IP válida, nunca None.

    Ver el modelo de confianza en el docstring del módulo. Para decidir un
    bloqueo hay que usar `get_client_ip_with_trust` y respetar su segundo valor.
    """
    return get_client_ip_with_trust(request)[0]


def get_user_agent(request):
    """User-Agent del cliente, acotado para que quepa en los modelos."""
    return request.META.get('HTTP_USER_AGENT', '')[:500]
