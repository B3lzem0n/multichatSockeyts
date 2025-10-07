import socket
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import io

HOST = 'localhost'
PORT = 5000
BUFFER_SIZE = 4096


def solicitar_archivo(filename):
    """Solicita un archivo al servidor y lo procesa."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        header = f"__file_request__|{filename}\n"
        s.sendall(header.encode())

        meta = s.recv(1024).decode(errors="ignore")
        if meta.startswith("__error__"):
            print("Error del servidor:", meta)
            return None, None

        if not meta.startswith("__file_info__"):
            print("Respuesta desconocida del servidor:", meta)
            return None, None

        parts = meta.strip().split("|")
        if len(parts) < 4:
            print("Respuesta incompleta del servidor")
            return None, None

        fname, size, mime = parts[1], int(parts[2]), parts[3]

        # Recibir datos binarios
        data = bytearray()
        remaining = size
        while remaining > 0:
            chunk = s.recv(min(BUFFER_SIZE, remaining))
            if not chunk:
                break
            data.extend(chunk)
            remaining -= len(chunk)

        return fname, (bytes(data), mime)


def mostrar_imagen(data, fname):
    """Muestra la imagen en una ventana Tkinter."""
    root = tk.Tk()
    root.title(f"Preview de {fname}")

    img = Image.open(io.BytesIO(data))
    photo = ImageTk.PhotoImage(img)

    lbl = tk.Label(root, image=photo)
    lbl.image = photo   # 🔑 Mantener referencia
    lbl.pack(padx=10, pady=10)

    def guardar():
        dest = filedialog.asksaveasfilename(initialfile=fname, title="Guardar imagen")
        if dest:
            with open(dest, "wb") as f:
                f.write(data)
            messagebox.showinfo("Guardado", f"Imagen guardada en {dest}")

    btn = tk.Button(root, text="Guardar en disco", command=guardar)
    btn.pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    filename = "g.jpg"  # Cambia al nombre del archivo que quieras pedir
    fname, result = solicitar_archivo(filename)

    if result:
        data, mime = result
        if mime.startswith("image/"):
            mostrar_imagen(data, fname)
        else:
            save = input(f"Archivo {fname} recibido ({len(data)} bytes). ¿Guardar en disco? (s/n): ")
            if save.lower() == "s":
                with open(f"recibido_{fname}", "wb") as f:
                    f.write(data)
                print(f"Archivo guardado como recibido_{fname}")
