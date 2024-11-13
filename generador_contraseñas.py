import random
import string

def generar_contraseña(longitud):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    while True:
        contraseña = ''.join(random.choice(caracteres) for _ in range(longitud))
        if (any(c.islower() for c in contraseña) and
            any(c.isupper() for c in contraseña) and
            any(c.isdigit() for c in contraseña) and
            any(c in string.punctuation for c in contraseña)):
            return contraseña

longitud_contraseña = int(input("Longitud de la contraseña: "))
while longitud_contraseña < 12:  # Para asegurar que la contraseña sea lo suficientemente larga
    print("La contraseña debe tener al menos 12 caracteres de longitud.")
    longitud_contraseña = int(input("Introduce una longitud válida para la contraseña: "))

contraseña_generada = generar_contraseña(longitud_contraseña)
print("Contraseña generada:", contraseña_generada)
