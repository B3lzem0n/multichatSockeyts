import socket
import os
import mimetypes

HOST = 'localhost'
PORT = 5000
BUFFER_SIZE = 4096

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Servidor] Esperando conexiones en {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        with conn:
            print(f"[Servidor] Conexión establecida con {addr}")

            # Recibir petición inicial
            request = conn.recv(BUFFER_SIZE).decode(errors="ignore").strip()
            if not request.startswith("__file_request__"):
                conn.sendall(b"__error__|Peticion invalida\n")
                continue

            filename = request.split("|", 1)[1]
            print(f"[Servidor] Petición de archivo: {filename}")

            if os.path.exists(filename) and os.path.isfile(filename):
                size = os.path.getsize(filename)
                mime, _ = mimetypes.guess_type(filename)
                mime = mime or "application/octet-stream"

                # Enviar cabecera con metadatos
                header = f"__file_info__|{os.path.basename(filename)}|{size}|{mime}\n"
                conn.sendall(header.encode())

                # Enviar archivo por bloques
                with open(filename, "rb") as f:
                    while (chunk := f.read(BUFFER_SIZE)):
                        conn.sendall(chunk)

                print(f"[Servidor] Archivo {filename} enviado ({size} bytes).")
            else:
                conn.sendall(b"__error__|Archivo no encontrado\n")
                print("[Servidor] Archivo no encontrado")
