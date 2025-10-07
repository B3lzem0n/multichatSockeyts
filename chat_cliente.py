# chat_cliente_corregido.py
# Cliente de chat con GUI (Tkinter).
# - Se conecta al servidor tras login (IP, puerto, usuario).
# - Envía mensajes y sube archivos por streaming.
# - Recibe avisos de archivos (anuncios) y permite preview o descarga.
# - Mantiene referencias a PhotoImage para evitar errores de Tkinter.

import socket
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog, messagebox
import os
import queue
from PIL import Image, ImageTk
import io
import time

BUFFER_SIZE = 65536
MAX_FILE_BYTES = 700 * 1024**3  # 700 GiB (ajusta si lo deseas)

recv_queue = queue.Queue()


def recv_line(sock):
    """Lee hasta '\n' desde el socket (bloqueante). Retorna str o None si la conexión se cerró."""
    data = bytearray()
    while True:
        try:
            ch = sock.recv(1)
        except Exception:
            return None
        if not ch:
            return None
        if ch == b'\n':
            break
        data.extend(ch)
    return data.decode(errors='ignore')


class ChatClient:
    def __init__(self):
        self.sock = None
        self.username = None
        self.running = False

        # announced_files: filename -> (size, mime)
        self.announced_files = {}

        # expected_downloads: filename -> (mode, path, preview_size)
        # mode: 'file' or 'memory' or 'preview'
        self.expected_downloads = {}
        self.expected_lock = threading.Lock()

        # Mantener referencias a PhotoImage para que Tk no las recolecte
        self.images_refs = []

        self.root = tk.Tk()
        self.root.title("Chat Cliente - Login")
        self.build_login_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    # ---------------- LOGIN UI ----------------
    def build_login_ui(self):
        # Limpiar si hay widgets previos
        for w in self.root.winfo_children():
            w.destroy()

        tk.Label(self.root, text="Servidor (IP):").grid(row=0, column=0, sticky="e")
        self.entry_host = tk.Entry(self.root)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1)

        tk.Label(self.root, text="Puerto:").grid(row=1, column=0, sticky="e")
        self.entry_port = tk.Entry(self.root)
        self.entry_port.insert(0, "6000")
        self.entry_port.grid(row=1, column=1)

        tk.Label(self.root, text="Usuario:").grid(row=2, column=0, sticky="e")
        self.entry_user = tk.Entry(self.root)
        self.entry_user.grid(row=2, column=1)

        tk.Button(self.root, text="Conectar", command=self.attempt_connect).grid(
            row=3, column=0, columnspan=2, pady=8
        )

    def attempt_connect(self):
        host = self.entry_host.get().strip()
        try:
            port = int(self.entry_port.get().strip())
        except:
            messagebox.showerror("Error", "Puerto inválido")
            return
        username = self.entry_user.get().strip()
        if not username:
            messagebox.showerror("Error", "Ingresa un nombre de usuario")
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            # enviar join
            self.sock.sendall((f"__join__|{username}\n").encode())
        except Exception as e:
            messagebox.showerror("Error de conexión", str(e))
            return

        self.username = username
        self.running = True
        threading.Thread(target=self.receiver_loop, daemon=True).start()
        # Construir UI de chat en la misma ventana raíz
        self.build_chat_ui()

    # ---------------- CHAT WINDOW ----------------
    def build_chat_ui(self):
        for w in self.root.winfo_children():
            w.destroy()

        self.root.title(f"Chat - {self.username}")

        self.txt = ScrolledText(self.root, state=tk.DISABLED, width=80, height=20, wrap=tk.WORD)
        self.txt.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

        self.entry = tk.Entry(self.root, width=60)
        self.entry.grid(row=1, column=0, padx=5, pady=5)
        self.entry.bind("<Return>", lambda e: self.send_message())

        tk.Button(self.root, text="Enviar", command=self.send_message).grid(row=1, column=1)
        tk.Button(self.root, text="Enviar archivo", command=self.send_file_dialog).grid(row=1, column=2)
        tk.Button(self.root, text="Cerrar", command=self.on_close).grid(row=1, column=3)

        self.root.after(100, self.process_recv_queue)

    # ---------------- UI HELPERS ----------------
    def append_text(self, text):
        self.txt.config(state=tk.NORMAL)
        self.txt.insert(tk.END, text + "\n")
        self.txt.see(tk.END)
        self.txt.config(state=tk.DISABLED)

    def append_widget(self, widget):
        self.txt.config(state=tk.NORMAL)
        self.txt.window_create(tk.END, window=widget)
        self.txt.insert(tk.END, "\n")
        self.txt.see(tk.END)
        self.txt.config(state=tk.DISABLED)

    # ---------------- QUEUE PROCESSOR ----------------
    def process_recv_queue(self):
        while True:
            try:
                typ, payload = recv_queue.get_nowait()
            except queue.Empty:
                break

            if typ == "msg":
                self.append_text(payload)

            elif typ == "file_notice":
                sender, filename, size, mime = payload
                self.announced_files[filename] = (size, mime)
                self.append_text(f"[{sender}] Archivo disponible: {filename} ({size} B)")
                btn = tk.Button(self.txt, text=f"Descargar {filename}",
                                command=lambda f=filename, m=mime: self.download_file(f, m))
                self.append_widget(btn)

            elif typ == "file_saved":
                fname, path = payload
                self.append_text(f"[Descarga completada] {fname} guardado en {path}")

            elif typ == "file_downloaded":
                fname, data, mime = payload

                # --- Bloque de visualización inline de imágenes ---
                if mime.startswith("image/"):
                    try:
                        image = Image.open(io.BytesIO(data))
                        photo = ImageTk.PhotoImage(image)

                        # Crear un label con la imagen
                        lbl = tk.Label(self.txt, image=photo)
                        lbl.image = photo  # evitar que el GC la borre
                        self.images_refs.append(photo)  # mantener referencia global

                        # Mostrar mensaje en el chat
                        self.append_text(f"[Servidor] Imagen recibida: {fname} ({len(data)} B)")
                        self.append_widget(lbl)

                        # Preguntar si quiere guardar la imagen
                        if messagebox.askyesno("Guardar imagen", f"La imagen '{fname}' se ha visualizado.\n¿Deseas guardarla ahora en disco?"):
                            dest = filedialog.asksaveasfilename(title=f"Guardar {fname}", initialfile=fname)
                            if dest:
                                try:
                                    with open(dest, "wb") as f:
                                        f.write(data)
                                    self.append_text(f"[Guardado] {fname} -> {dest}")
                                except Exception as e:
                                    self.append_text(f"[Error guardando] {e}")

                    except Exception as e:
                        self.append_text(f"[Error mostrando imagen] {e}")

                else:
                    # --- Bloque original para otros tipos de archivo ---
                    self.append_text(f"[Servidor] Archivo descargado en memoria: {fname} ({len(data)} B, tipo: {mime})")
                    # Preguntar si desea guardar en disco
                    if messagebox.askyesno("Guardar archivo", f"¿Deseas guardar {fname} en disco?"):
                        dest = filedialog.asksaveasfilename(title=f"Guardar {fname}", initialfile=fname)
                        if dest:
                            try:
                                with open(dest, "wb") as f:
                                    f.write(data)
                                self.append_text(f"[Guardado] {fname} -> {dest}")
                            except Exception as e:
                                self.append_text(f"[Error guardando] {e}")

            elif typ == "file_preview":
                fname, data_bytes, mime, done = payload
                if mime.startswith("image/"):
                    try:
                        image = Image.open(io.BytesIO(data_bytes))
                        photo = ImageTk.PhotoImage(image)
                        lbl = tk.Label(self.txt, image=photo)
                        lbl.image = photo
                        self.images_refs.append(photo)
                        self.append_text(f"[Preview] {fname} ({len(data_bytes)} B)")
                        self.append_widget(lbl)
                    except Exception:
                        # bytes insuficientes para decodificar como imagen -> mostrar progreso
                        self.append_text(f"[Preview parcial] {fname} ({len(data_bytes)} B recibidos)...")
                elif mime.startswith("text/") or mime in ("application/json", "application/javascript"):
                    try:
                        s = data_bytes.decode("utf-8", errors="ignore")
                        self.append_text(f"[Preview texto] {fname}:\n{s[:1000]}")
                    except:
                        self.append_text(f"[Preview parcial texto] {fname} ({len(data_bytes)} B)")
                else:
                    self.append_text(f"[Preview] {fname}: {len(data_bytes)} bytes recibidos (tipo {mime})")
                if done:
                    self.append_text(f"[Preview completo] {fname}")

            elif typ == "error":
                self.append_text(f"[Error] {payload}")

        self.root.after(100, self.process_recv_queue)

    # ---------------- RECEIVER (hilo) ----------------
    def receiver_loop(self):
        try:
            while self.running:
                header = recv_line(self.sock)
                if header is None:
                    recv_queue.put(("msg", "[Sistema] Conexión cerrada por el servidor"))
                    break

                # Mensaje de chat
                if header.startswith("__msg__|"):
                    parts = header.split("|", 2)
                    if len(parts) == 3:
                        user, texto = parts[1], parts[2]
                        recv_queue.put(("msg", f"{user}: {texto}"))

                # Aviso de archivo (anuncio)
                elif header.startswith("__srv_file_notice__|"):
                    parts = header.split("|")
                    # formato: __srv_file_notice__|target|filename|size|mime
                    if len(parts) >= 5:
                        target, filename, size, mime = parts[1], parts[2], int(parts[3]), parts[4]
                        if target == "ALL" or target == self.username:
                            recv_queue.put(("file_notice", ("Servidor", filename, size, mime)))

                # Preview enviado por el servidor (header + preview bytes)
                elif header.startswith("__srv_file_preview__|"):
                    parts = header.split("|")
                    # formato: __srv_file_preview__|filename|size|mime
                    if len(parts) >= 4:
                        fname, size, mime = parts[1], int(parts[2]), parts[3]
                        with self.expected_lock:
                            expected = self.expected_downloads.pop(fname, None)
                        if expected is None or expected[0] not in ("memory", "preview"):
                            # no esperado -> leer y descartar
                            remaining = size
                            while remaining > 0:
                                chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                if not chunk:
                                    break
                                remaining -= len(chunk)
                            recv_queue.put(("error", f"No se esperaba el preview {fname}"))
                            continue

                        # leer preview bytes y publicar (parciales permitidos)
                        try:
                            buf = bytearray()
                            remaining = size
                            while remaining > 0:
                                chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                if not chunk:
                                    raise IOError("Conexión interrumpida")
                                buf.extend(chunk)
                                remaining -= len(chunk)
                                # publicar parcial (aquí enviamos la acumulación actual)
                                recv_queue.put(("file_preview", (fname, bytes(buf), mime, remaining == 0)))
                        except Exception as e:
                            recv_queue.put(("error", f"Error recibiendo preview {fname}: {e}"))

                # Descarga completa (header + bytes)
                elif header.startswith("__srv_file_download__|"):
                    parts = header.split("|")
                    # formato: __srv_file_download__|filename|size|mime
                    if len(parts) >= 4:
                        fname, size, mime = parts[1], int(parts[2]), parts[3]
                        with self.expected_lock:
                            expected = self.expected_downloads.pop(fname, None)
                        if expected is None:
                            # no esperado -> leer y descartar
                            remaining = size
                            while remaining > 0:
                                chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                if not chunk:
                                    break
                                remaining -= len(chunk)
                            recv_queue.put(("error", f"No se esperaba el archivo {fname}"))
                            continue

                        mode, path, _ = expected
                        if mode == "file":
                            # escribir directamente en disco por streaming
                            try:
                                with open(path, "wb") as f:
                                    remaining = size
                                    while remaining > 0:
                                        chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                        if not chunk:
                                            raise IOError("Conexión interrumpida")
                                        f.write(chunk)
                                        remaining -= len(chunk)
                                recv_queue.put(("file_saved", (fname, path)))
                            except Exception as e:
                                recv_queue.put(("error", f"Error guardando {fname}: {e}"))
                        else:
                            # memory: leer todo a memoria y luego enviar al GUI
                            try:
                                buf = bytearray()
                                remaining = size
                                while remaining > 0:
                                    chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                    if not chunk:
                                        raise IOError("Conexión interrumpida")
                                    buf.extend(chunk)
                                    remaining -= len(chunk)
                                recv_queue.put(("file_downloaded", (fname, bytes(buf), mime)))
                            except Exception as e:
                                recv_queue.put(("error", f"Error recibiendo {fname}: {e}"))

                elif header.startswith("__error__|"):
                    recv_queue.put(("error", header))
                else:
                    recv_queue.put(("msg", f"[Raw header] {header}"))

        except Exception as e:
            recv_queue.put(("error", str(e)))
        finally:
            self.running = False
            try:
                if self.sock:
                    self.sock.close()
            except:
                pass

    # ---------------- PETICIÓN DE DESCARGA ----------------
    def download_file(self, filename, mime):
        """
        Prepara la descarga según el tipo:
          - imágenes: pregunta si visualizar (memory) o guardar en disco (file)
          - otros: pide ruta y guarda a disco (file)
        """
        try:
            if mime.startswith("image/"):
                # Preguntar al usuario si desea visualizar (memory) o guardar (file)
                choice = messagebox.askyesnocancel(
                    "Archivo de Imagen",
                    f"¿Deseas visualizar '{filename}' en el chat?\n\n'Sí': Mostrar en el chat (descarga a memoria).\n'No': Guardar directamente a disco.\n'Cancelar': Anular.",
                    icon='question'
                )

                if choice is None:  # Cancelar
                    return

                if choice:  # Sí: Visualizar en el chat (modo memory)
                    mode = "memory"
                    path = None
                    preview_size = None
                    self.append_text(f"[Descarga] Solicitando imagen completa para visualización en chat...")
                else:  # No: Guardar directamente a disco (modo file)
                    dest = filedialog.asksaveasfilename(title=f"Guardar {filename}", initialfile=filename)
                    if not dest:
                        return
                    mode = "file"
                    path = dest
                    preview_size = None
                    self.append_text(f"[Descarga] Solicitando archivo completo para guardar en disco...")
            else:
                # Otros archivos: siempre guardar a disco (modo file)
                dest = filedialog.asksaveasfilename(title=f"Guardar {filename}", initialfile=filename)
                if not dest:
                    return
                mode = "file"
                path = dest
                preview_size = None
                self.append_text(f"[Descarga] Solicitando archivo para guardar en {path}...")

            # Establecer expectativa y enviar petición al servidor
            with self.expected_lock:
                # Usar 'full' porque tanto 'memory' (para visualización) como 'file' (para guardado)
                # requieren la descarga de todos los bytes.
                self.expected_downloads[filename] = (mode, path, preview_size)
                self.sock.sendall((f"__srv_file_request__|{filename}|full\n").encode())

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo solicitar archivo: {e}")

    # ---------------- ENVIOS ----------------
    def send_message(self):
        texto = self.entry.get().strip()
        if not texto:
            return
        header = f"__msg__|{self.username}|{texto}\n"
        try:
            self.sock.sendall(header.encode())
            self.entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo enviar: {e}")

    def send_file_dialog(self):
        path = filedialog.askopenfilename(title="Seleccionar archivo para enviar al servidor")
        if not path:
            return
        size = os.path.getsize(path)
        if size < 1 or size > MAX_FILE_BYTES:
            messagebox.showerror("Error", "Tamaño de archivo no permitido (1B - 700GB).")
            return
        filename = os.path.basename(path)
        try:
            # enviar header y luego stream
            self.sock.sendall((f"__file_upload__|{filename}|{size}\n").encode())
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
            messagebox.showinfo("OK", f"Archivo {filename} enviado al servidor.")
        except Exception as e:
            messagebox.showerror("Error envío", str(e))

    # ---------------- CIERRE ----------------
    def on_close(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        try:
            self.root.destroy()
        except:
            pass
        # asegurar salida completa
        os._exit(0)


if __name__ == "__main__":
    ChatClient()
# chat_cliente_corregido.py
# Cliente de chat con GUI (Tkinter).
# - Se conecta al servidor tras login (IP, puerto, usuario).
# - Envía mensajes y sube archivos por streaming.
# - Recibe avisos de archivos (anuncios) y permite preview o descarga.
# - Mantiene referencias a PhotoImage para evitar errores de Tkinter.

import socket
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog, messagebox
import os
import queue
from PIL import Image, ImageTk
import io
import time

BUFFER_SIZE = 65536
MAX_FILE_BYTES = 700 * 1024**3  # 700 GiB (ajusta si lo deseas)

recv_queue = queue.Queue()


def recv_line(sock):
    """Lee hasta '\n' desde el socket (bloqueante). Retorna str o None si la conexión se cerró."""
    data = bytearray()
    while True:
        try:
            ch = sock.recv(1)
        except Exception:
            return None
        if not ch:
            return None
        if ch == b'\n':
            break
        data.extend(ch)
    return data.decode(errors='ignore')


class ChatClient:
    def __init__(self):
        self.sock = None
        self.username = None
        self.running = False

        # announced_files: filename -> (size, mime)
        self.announced_files = {}

        # expected_downloads: filename -> (mode, path, preview_size)
        # mode: 'file' or 'memory' or 'preview'
        self.expected_downloads = {}
        self.expected_lock = threading.Lock()

        # Mantener referencias a PhotoImage para que Tk no las recolecte
        self.images_refs = []

        self.root = tk.Tk()
        self.root.title("Chat Cliente - Login")
        self.build_login_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    # ---------------- LOGIN UI ----------------
    def build_login_ui(self):
        # Limpiar si hay widgets previos
        for w in self.root.winfo_children():
            w.destroy()

        tk.Label(self.root, text="Servidor (IP):").grid(row=0, column=0, sticky="e")
        self.entry_host = tk.Entry(self.root)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1)

        tk.Label(self.root, text="Puerto:").grid(row=1, column=0, sticky="e")
        self.entry_port = tk.Entry(self.root)
        self.entry_port.insert(0, "6000")
        self.entry_port.grid(row=1, column=1)

        tk.Label(self.root, text="Usuario:").grid(row=2, column=0, sticky="e")
        self.entry_user = tk.Entry(self.root)
        self.entry_user.grid(row=2, column=1)

        tk.Button(self.root, text="Conectar", command=self.attempt_connect).grid(
            row=3, column=0, columnspan=2, pady=8
        )

    def attempt_connect(self):
        host = self.entry_host.get().strip()
        try:
            port = int(self.entry_port.get().strip())
        except:
            messagebox.showerror("Error", "Puerto inválido")
            return
        username = self.entry_user.get().strip()
        if not username:
            messagebox.showerror("Error", "Ingresa un nombre de usuario")
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            # enviar join
            self.sock.sendall((f"__join__|{username}\n").encode())
        except Exception as e:
            messagebox.showerror("Error de conexión", str(e))
            return

        self.username = username
        self.running = True
        threading.Thread(target=self.receiver_loop, daemon=True).start()
        # Construir UI de chat en la misma ventana raíz
        self.build_chat_ui()

    # ---------------- CHAT WINDOW ----------------
    def build_chat_ui(self):
        for w in self.root.winfo_children():
            w.destroy()

        self.root.title(f"Chat - {self.username}")

        self.txt = ScrolledText(self.root, state=tk.DISABLED, width=80, height=20, wrap=tk.WORD)
        self.txt.grid(row=0, column=0, columnspan=4, padx=5, pady=5)

        self.entry = tk.Entry(self.root, width=60)
        self.entry.grid(row=1, column=0, padx=5, pady=5)
        self.entry.bind("<Return>", lambda e: self.send_message())

        tk.Button(self.root, text="Enviar", command=self.send_message).grid(row=1, column=1)
        tk.Button(self.root, text="Enviar archivo", command=self.send_file_dialog).grid(row=1, column=2)
        tk.Button(self.root, text="Cerrar", command=self.on_close).grid(row=1, column=3)

        self.root.after(100, self.process_recv_queue)

    # ---------------- UI HELPERS ----------------
    def append_text(self, text):
        self.txt.config(state=tk.NORMAL)
        self.txt.insert(tk.END, text + "\n")
        self.txt.see(tk.END)
        self.txt.config(state=tk.DISABLED)

    def append_widget(self, widget):
        self.txt.config(state=tk.NORMAL)
        self.txt.window_create(tk.END, window=widget)
        self.txt.insert(tk.END, "\n")
        self.txt.see(tk.END)
        self.txt.config(state=tk.DISABLED)

    # ---------------- QUEUE PROCESSOR ----------------
    def process_recv_queue(self):
        while True:
            try:
                typ, payload = recv_queue.get_nowait()
            except queue.Empty:
                break

            if typ == "msg":
                self.append_text(payload)

            elif typ == "file_notice":
                sender, filename, size, mime = payload
                self.announced_files[filename] = (size, mime)
                self.append_text(f"[{sender}] Archivo disponible: {filename} ({size} B)")
                btn = tk.Button(self.txt, text=f"Descargar {filename}",
                                command=lambda f=filename, m=mime: self.download_file(f, m))
                self.append_widget(btn)

            elif typ == "file_saved":
                fname, path = payload
                self.append_text(f"[Descarga completada] {fname} guardado en {path}")

            elif typ == "file_downloaded":
                fname, data, mime = payload

                # --- Bloque de visualización inline de imágenes ---
                if mime.startswith("image/"):
                    try:
                        image = Image.open(io.BytesIO(data))
                        photo = ImageTk.PhotoImage(image)

                        # Crear un label con la imagen
                        lbl = tk.Label(self.txt, image=photo)
                        lbl.image = photo  # evitar que el GC la borre
                        self.images_refs.append(photo)  # mantener referencia global

                        # Mostrar mensaje en el chat
                        self.append_text(f"[Servidor] Imagen recibida: {fname} ({len(data)} B)")
                        self.append_widget(lbl)

                        # Preguntar si quiere guardar la imagen
                        if messagebox.askyesno("Guardar imagen", f"La imagen '{fname}' se ha visualizado.\n¿Deseas guardarla ahora en disco?"):
                            dest = filedialog.asksaveasfilename(title=f"Guardar {fname}", initialfile=fname)
                            if dest:
                                try:
                                    with open(dest, "wb") as f:
                                        f.write(data)
                                    self.append_text(f"[Guardado] {fname} -> {dest}")
                                except Exception as e:
                                    self.append_text(f"[Error guardando] {e}")

                    except Exception as e:
                        self.append_text(f"[Error mostrando imagen] {e}")

                else:
                    # --- Bloque original para otros tipos de archivo ---
                    self.append_text(f"[Servidor] Archivo descargado en memoria: {fname} ({len(data)} B, tipo: {mime})")
                    # Preguntar si desea guardar en disco
                    if messagebox.askyesno("Guardar archivo", f"¿Deseas guardar {fname} en disco?"):
                        dest = filedialog.asksaveasfilename(title=f"Guardar {fname}", initialfile=fname)
                        if dest:
                            try:
                                with open(dest, "wb") as f:
                                    f.write(data)
                                self.append_text(f"[Guardado] {fname} -> {dest}")
                            except Exception as e:
                                self.append_text(f"[Error guardando] {e}")

            elif typ == "file_preview":
                fname, data_bytes, mime, done = payload
                if mime.startswith("image/"):
                    try:
                        image = Image.open(io.BytesIO(data_bytes))
                        photo = ImageTk.PhotoImage(image)
                        lbl = tk.Label(self.txt, image=photo)
                        lbl.image = photo
                        self.images_refs.append(photo)
                        self.append_text(f"[Preview] {fname} ({len(data_bytes)} B)")
                        self.append_widget(lbl)
                    except Exception:
                        # bytes insuficientes para decodificar como imagen -> mostrar progreso
                        self.append_text(f"[Preview parcial] {fname} ({len(data_bytes)} B recibidos)...")
                elif mime.startswith("text/") or mime in ("application/json", "application/javascript"):
                    try:
                        s = data_bytes.decode("utf-8", errors="ignore")
                        self.append_text(f"[Preview texto] {fname}:\n{s[:1000]}")
                    except:
                        self.append_text(f"[Preview parcial texto] {fname} ({len(data_bytes)} B)")
                else:
                    self.append_text(f"[Preview] {fname}: {len(data_bytes)} bytes recibidos (tipo {mime})")
                if done:
                    self.append_text(f"[Preview completo] {fname}")

            elif typ == "error":
                self.append_text(f"[Error] {payload}")

        self.root.after(100, self.process_recv_queue)

    # ---------------- RECEIVER (hilo) ----------------
    def receiver_loop(self):
        try:
            while self.running:
                header = recv_line(self.sock)
                if header is None:
                    recv_queue.put(("msg", "[Sistema] Conexión cerrada por el servidor"))
                    break

                # Mensaje de chat
                if header.startswith("__msg__|"):
                    parts = header.split("|", 2)
                    if len(parts) == 3:
                        user, texto = parts[1], parts[2]
                        recv_queue.put(("msg", f"{user}: {texto}"))

                # Aviso de archivo (anuncio)
                elif header.startswith("__srv_file_notice__|"):
                    parts = header.split("|")
                    # formato: __srv_file_notice__|target|filename|size|mime
                    if len(parts) >= 5:
                        target, filename, size, mime = parts[1], parts[2], int(parts[3]), parts[4]
                        if target == "ALL" or target == self.username:
                            recv_queue.put(("file_notice", ("Servidor", filename, size, mime)))

                # Preview enviado por el servidor (header + preview bytes)
                elif header.startswith("__srv_file_preview__|"):
                    parts = header.split("|")
                    # formato: __srv_file_preview__|filename|size|mime
                    if len(parts) >= 4:
                        fname, size, mime = parts[1], int(parts[2]), parts[3]
                        with self.expected_lock:
                            expected = self.expected_downloads.pop(fname, None)
                        if expected is None or expected[0] not in ("memory", "preview"):
                            # no esperado -> leer y descartar
                            remaining = size
                            while remaining > 0:
                                chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                if not chunk:
                                    break
                                remaining -= len(chunk)
                            recv_queue.put(("error", f"No se esperaba el preview {fname}"))
                            continue

                        # leer preview bytes y publicar (parciales permitidos)
                        try:
                            buf = bytearray()
                            remaining = size
                            while remaining > 0:
                                chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                if not chunk:
                                    raise IOError("Conexión interrumpida")
                                buf.extend(chunk)
                                remaining -= len(chunk)
                                # publicar parcial (aquí enviamos la acumulación actual)
                                recv_queue.put(("file_preview", (fname, bytes(buf), mime, remaining == 0)))
                        except Exception as e:
                            recv_queue.put(("error", f"Error recibiendo preview {fname}: {e}"))

                # Descarga completa (header + bytes)
                elif header.startswith("__srv_file_download__|"):
                    parts = header.split("|")
                    # formato: __srv_file_download__|filename|size|mime
                    if len(parts) >= 4:
                        fname, size, mime = parts[1], int(parts[2]), parts[3]
                        with self.expected_lock:
                            expected = self.expected_downloads.pop(fname, None)
                        if expected is None:
                            # no esperado -> leer y descartar
                            remaining = size
                            while remaining > 0:
                                chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                if not chunk:
                                    break
                                remaining -= len(chunk)
                            recv_queue.put(("error", f"No se esperaba el archivo {fname}"))
                            continue

                        mode, path, _ = expected
                        if mode == "file":
                            # escribir directamente en disco por streaming
                            try:
                                with open(path, "wb") as f:
                                    remaining = size
                                    while remaining > 0:
                                        chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                        if not chunk:
                                            raise IOError("Conexión interrumpida")
                                        f.write(chunk)
                                        remaining -= len(chunk)
                                recv_queue.put(("file_saved", (fname, path)))
                            except Exception as e:
                                recv_queue.put(("error", f"Error guardando {fname}: {e}"))
                        else:
                            # memory: leer todo a memoria y luego enviar al GUI
                            try:
                                buf = bytearray()
                                remaining = size
                                while remaining > 0:
                                    chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
                                    if not chunk:
                                        raise IOError("Conexión interrumpida")
                                    buf.extend(chunk)
                                    remaining -= len(chunk)
                                recv_queue.put(("file_downloaded", (fname, bytes(buf), mime)))
                            except Exception as e:
                                recv_queue.put(("error", f"Error recibiendo {fname}: {e}"))

                elif header.startswith("__error__|"):
                    recv_queue.put(("error", header))
                else:
                    recv_queue.put(("msg", f"[Raw header] {header}"))

        except Exception as e:
            recv_queue.put(("error", str(e)))
        finally:
            self.running = False
            try:
                if self.sock:
                    self.sock.close()
            except:
                pass

    # ---------------- PETICIÓN DE DESCARGA ----------------
    def download_file(self, filename, mime):
        """
        Prepara la descarga según el tipo:
          - imágenes: pregunta si visualizar (memory) o guardar en disco (file)
          - otros: pide ruta y guarda a disco (file)
        """
        try:
            if mime.startswith("image/"):
                # Preguntar al usuario si desea visualizar (memory) o guardar (file)
                choice = messagebox.askyesnocancel(
                    "Archivo de Imagen",
                    f"¿Deseas visualizar '{filename}' en el chat?\n\n'Sí': Mostrar en el chat (descarga a memoria).\n'No': Guardar directamente a disco.\n'Cancelar': Anular.",
                    icon='question'
                )

                if choice is None:  # Cancelar
                    return

                if choice:  # Sí: Visualizar en el chat (modo memory)
                    mode = "memory"
                    path = None
                    preview_size = None
                    self.append_text(f"[Descarga] Solicitando imagen completa para visualización en chat...")
                else:  # No: Guardar directamente a disco (modo file)
                    dest = filedialog.asksaveasfilename(title=f"Guardar {filename}", initialfile=filename)
                    if not dest:
                        return
                    mode = "file"
                    path = dest
                    preview_size = None
                    self.append_text(f"[Descarga] Solicitando archivo completo para guardar en disco...")
            else:
                # Otros archivos: siempre guardar a disco (modo file)
                dest = filedialog.asksaveasfilename(title=f"Guardar {filename}", initialfile=filename)
                if not dest:
                    return
                mode = "file"
                path = dest
                preview_size = None
                self.append_text(f"[Descarga] Solicitando archivo para guardar en {path}...")

            # Establecer expectativa y enviar petición al servidor
            with self.expected_lock:
                # Usar 'full' porque tanto 'memory' (para visualización) como 'file' (para guardado)
                # requieren la descarga de todos los bytes.
                self.expected_downloads[filename] = (mode, path, preview_size)
                self.sock.sendall((f"__srv_file_request__|{filename}|full\n").encode())

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo solicitar archivo: {e}")

    # ---------------- ENVIOS ----------------
    def send_message(self):
        texto = self.entry.get().strip()
        if not texto:
            return
        header = f"__msg__|{self.username}|{texto}\n"
        try:
            self.sock.sendall(header.encode())
            self.entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo enviar: {e}")

    def send_file_dialog(self):
        path = filedialog.askopenfilename(title="Seleccionar archivo para enviar al servidor")
        if not path:
            return
        size = os.path.getsize(path)
        if size < 1 or size > MAX_FILE_BYTES:
            messagebox.showerror("Error", "Tamaño de archivo no permitido (1B - 700GB).")
            return
        filename = os.path.basename(path)
        try:
            # enviar header y luego stream
            self.sock.sendall((f"__file_upload__|{filename}|{size}\n").encode())
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
            messagebox.showinfo("OK", f"Archivo {filename} enviado al servidor.")
        except Exception as e:
            messagebox.showerror("Error envío", str(e))

    # ---------------- CIERRE ----------------
    def on_close(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        try:
            self.root.destroy()
        except:
            pass
        # asegurar salida completa
        os._exit(0)


if __name__ == "__main__":
    ChatClient()
