"""Paquete de tests L1 de myapp.

SUSTITUYE al antiguo `myapp/tests.py` (único fichero de PRODUCCIÓN que toca el plan
de pruebas, §7). Aquel `tests.py` no tenía tests: su cuerpo era

    '''from django.test import TestCase
    # Create your tests here.'''
    import os
    key = os.urandom(32)
    print(key)

—una plantilla de startapp con un `print(os.urandom(32))` a NIVEL DE MÓDULO. Eso
imprimía 32 bytes aleatorios a stdout en cuanto algo importaba `myapp.tests` (p. ej.
`manage.py test` al autodescubrir). Al convertirlo en paquete ese `print` desaparece:
el efecto de importación de nivel de módulo se elimina y en su lugar quedan
`settings_test.py`, `conftest.py` y los ficheros `test_*.py`.

L1 corre DENTRO del contenedor `web` (la pila levantada): en el host, importar Django
falla (settings.py:39 exige DJANGO_SECRET_KEY y minio_service instancia a nivel de
módulo). Ver §2.1 del PLAN-DE-PRUEBAS.md.
"""
