# chat_servidor.py (versión corregida y actualizada)
import socket
import threading
import os
import mimetypes
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog, messagebox
import queue
import time
import shutil

# ============================
# Configuración del servidor
# ============================
HOST = "0.0.0.0"
PORT = 6000
BUFFER_SIZE = 65536
MAX_FILE_BYTES = 700 * 1024**3  # 700 GB

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

clients_lock = threading.Lock()
clients = {}  # conn -> username
files_lock = threading.Lock()
files_db = {}  # file_id -> {filename, path, size, uploader, mimetype}
file_counter = 0

gui_queue = queue.Queue()

# ============================
# Funciones auxiliares
# ============================
def log_gui(msg: str):
    gui_queue.put(msg)

def recv_line(conn):
    """Lee hasta '\\n' desde conn y devuelve la línea (sin el '\\n'). Retorna None si la conexión se cierra."""
    data = bytearray()
    while True:
        try:
            ch = conn.recv(1)
        except Exception:
            return None
        if not ch:
            return None
        if ch == b"\n":
            break
        data.extend(ch)
    return data.decode(errors="ignore")

# ============================
# Manejo de clientes
# ============================
def handle_client(conn, addr):
    global file_counter
    try:
        line = recv_line(conn)
        if not line or not line.startswith("__join__|"):
            conn.close()
            return
        username = line.split("|", 1)[1].strip()
        with clients_lock:
            clients[conn] = username
        log_gui(f"{username} conectado desde {addr}")
        broadcast_msg("Servidor", f"{username} se ha conectado.", exclude=conn)

        while True:
            header = recv_line(conn)
            if header is None:
                break

            # ========== Mensajes de chat ==========
            if header.startswith("__msg__|"):
                parts = header.split("|", 2)
                if len(parts) == 3:
                    user, texto = parts[1], parts[2]
                    broadcast_msg(user, texto)
                    log_gui(f"{user}: {texto}")

            # ========== Subida de archivos ==========
            elif header.startswith("__file_upload__|"):
                parts = header.split("|")
                if len(parts) < 3:
                    log_gui(f"[WARN] Header file_upload inválido desde {clients.get(conn)}")
                    continue
                filename, size = parts[1], int(parts[2])
                if size < 1 or size > MAX_FILE_BYTES:
                    log_gui(f"[WARN] Tamaño inválido para archivo {filename} de {clients.get(conn)}")
                    continue
                safe_name = f"{int(time.time())}_{username}_{os.path.basename(filename)}"
                path = os.path.join(UPLOAD_DIR, safe_name)
                try:
                    with open(path, "wb") as f:
                        remaining = size
                        while remaining > 0:
                            chunk = conn.recv(min(BUFFER_SIZE, remaining))
                            if not chunk:
                                break
                            f.write(chunk)
                            remaining -= len(chunk)
                    if remaining == 0:
                        mime, _ = mimetypes.guess_type(filename)
                        if not mime:
                            mime = "application/octet-stream"
                        with files_lock:
                            fid = str(file_counter)
                            file_counter += 1
                            files_db[fid] = {
                                "filename": filename,
                                "path": path,
                                "size": size,
                                "uploader": username,
                                "mimetype": mime,
                            }
                        log_gui(f"Archivo recibido de {username}: {filename} ({size} B)")
                    else:
                        log_gui(f"Error recibiendo archivo de {username}: transmisión incompleta")
                        try:
                            os.remove(path)
                        except:
                            pass
                except Exception as e:
                    log_gui(f"Error al guardar archivo de {username}: {e}")
                    try:
                        if os.path.exists(path):
                            os.remove(path)
                    except:
                        pass

            # ========== Descarga o preview ==========
            elif header.startswith("__srv_file_request__|"):
                parts = header.split("|")
                if len(parts) < 2:
                    continue
                filename = parts[1].strip()
                mode = "full"
                preview_size = None
                if len(parts) >= 3 and parts[2]:
                    mode = parts[2]
                if len(parts) >= 4 and parts[3]:
                    try:
                        preview_size = int(parts[3])
                    except:
                        preview_size = None

                entry = None
                with files_lock:
                    for f in files_db.values():
                        if f["filename"] == filename:
                            entry = f
                            break

                if not entry:
                    try:
                        conn.sendall(f"__error__|file_not_found|{filename}\n".encode())
                    except:
                        pass
                    log_gui(f"Solicitud de archivo no encontrado: {filename} por {clients.get(conn)}")
                    continue

                mime = entry.get("mimetype") or mimetypes.guess_type(entry["filename"])[0] or "application/octet-stream"

                try:
                    # Enviar preview
                    if mode == "preview" and preview_size:
                        to_send = min(preview_size, entry["size"])
                        conn.sendall(f"__srv_file_preview__|{entry['filename']}|{to_send}|{mime}\n".encode())
                        sent = 0
                        with open(entry["path"], "rb") as fp:
                            while sent < to_send:
                                chunk = fp.read(min(BUFFER_SIZE, to_send - sent))
                                if not chunk:
                                    break
                                conn.sendall(chunk)
                                sent += len(chunk)
                        log_gui(f"Preview ({sent} bytes) enviado de '{filename}' a {clients.get(conn)}")

                    # Enviar archivo completo
                    else:
                        conn.sendall(f"__srv_file_download__|{entry['filename']}|{entry['size']}|{mime}\n".encode())
                        with open(entry["path"], "rb") as fp:
                            while True:
                                chunk = fp.read(BUFFER_SIZE)
                                if not chunk:
                                    break
                                conn.sendall(chunk)
                        log_gui(f"Archivo '{filename}' enviado a {clients.get(conn)}")
                except Exception as e:
                    log_gui(f"Error enviando archivo '{filename}' a {clients.get(conn)}: {e}")

            else:
                log_gui(f"[RAW_HEADER] {clients.get(conn)} -> {header}")

    except Exception as e:
        log_gui(f"Error cliente {addr}: {e}")
    finally:
        with clients_lock:
            user = clients.pop(conn, None)
        if user:
            broadcast_msg("Servidor", f"{user} se ha desconectado.")
            log_gui(f"{user} desconectado.")
        try:
            conn.close()
        except:
            pass

# ============================
# Funciones de broadcast
# ============================
def broadcast_msg(user, texto, exclude=None):
    header = f"__msg__|{user}|{texto}\n".encode()
    with clients_lock:
        for c in list(clients.keys()):
            if c == exclude:
                continue
            try:
                c.sendall(header)
            except:
                pass

# ============================
# Funciones de archivos
# ============================
def register_file(path, filename, uploader="Servidor"):
    global file_counter
    size = os.path.getsize(path)
    safe_name = f"{int(time.time())}_{uploader}_{os.path.basename(filename)}"
    new_path = os.path.join(UPLOAD_DIR, safe_name)
    if os.path.abspath(path) != os.path.abspath(new_path):
        shutil.copy(path, new_path)
    mime, _ = mimetypes.guess_type(filename)
    if not mime:
        mime = "application/octet-stream"
    with files_lock:
        fid = str(file_counter)
        file_counter += 1
        files_db[fid] = {
            "filename": filename,
            "path": new_path,
            "size": size,
            "uploader": uploader,
            "mimetype": mime,
        }
    return files_db[fid]

def announce_file_all(filepath, filename):
    entry = register_file(filepath, filename)
    mime = entry.get("mimetype", "application/octet-stream")
    header = f"__srv_file_notice__|ALL|{filename}|{entry['size']}|{mime}\n".encode()
    with clients_lock:
        for c in list(clients.keys()):
            try:
                c.sendall(header)
            except:
                pass
    log_gui(f"Archivo anunciado a TODOS: {filename}")

def announce_file_user(filepath, filename, target_user):
    entry = register_file(filepath, filename)
    mime = entry.get("mimetype", "application/octet-stream")
    header = f"__srv_file_notice__|{target_user}|{filename}|{entry['size']}|{mime}\n".encode()
    target_conn = None
    with clients_lock:
        for c, u in clients.items():
            if u == target_user:
                target_conn = c
                break
    if not target_conn:
        log_gui(f"Usuario {target_user} no encontrado.")
        return
    try:
        target_conn.sendall(header)
        log_gui(f"Archivo anunciado a {target_user}: {filename}")
    except Exception as e:
        log_gui(f"Error anunciando archivo a {target_user}: {e}")

# ============================
# Arranque del servidor
# ============================
def start_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(50)
    log_gui(f"Servidor escuchando en {HOST}:{PORT}")

    def accept_loop():
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return srv

# ============================
# GUI
# ============================
def process_gui_queue():
    while True:
        try:
            msg = gui_queue.get_nowait()
        except queue.Empty:
            break
        text_area.insert(tk.END, msg + "\n")
        text_area.see(tk.END)
        refresh_clients()
        refresh_files()
    root.after(200, process_gui_queue)

def refresh_clients():
    with clients_lock:
        client_listbox.delete(0, tk.END)
        for u in clients.values():
            client_listbox.insert(tk.END, u)

def refresh_files():
    with files_lock:
        files_listbox.delete(0, tk.END)
        for fid, f in files_db.items():
            files_listbox.insert(
                tk.END, f"{fid} | {f['filename']} ({f['size']} B) de {f['uploader']}"
            )

def announce_selected_file_all():
    sel = files_listbox.curselection()
    if not sel:
        messagebox.showinfo("Info", "Selecciona un archivo recibido.")
        return
    fid = list(files_db.keys())[sel[0]]
    f = files_db[fid]
    announce_file_all(f["path"], f["filename"])

def announce_selected_file_user():
    sel_f = files_listbox.curselection()
    sel_c = client_listbox.curselection()
    if not sel_f or not sel_c:
        messagebox.showinfo("Info", "Selecciona un archivo y un cliente.")
        return
    fid = list(files_db.keys())[sel_f[0]]
    f = files_db[fid]
    user = client_listbox.get(sel_c[0])
    announce_file_user(f["path"], f["filename"], user)

def announce_local_file_all():
    path = filedialog.askopenfilename(title="Seleccionar archivo local")
    if not path:
        return
    filename = os.path.basename(path)
    announce_file_all(path, filename)

def announce_local_file_user():
    sel_c = client_listbox.curselection()
    if not sel_c:
        messagebox.showinfo("Info", "Selecciona un cliente.")
        return
    user = client_listbox.get(sel_c[0])
    path = filedialog.askopenfilename(title="Seleccionar archivo local")
    if not path:
        return
    filename = os.path.basename(path)
    announce_file_user(path, filename, user)

def on_close():
    with clients_lock:
        for c in list(clients.keys()):
            try:
                c.close()
            except:
                pass
    root.quit()

# ============================
# Main GUI loop
# ============================
root = tk.Tk()
root.title("Servidor Chat")

frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

text_area = ScrolledText(frame, height=20)
text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

right = tk.Frame(frame)
right.pack(side=tk.RIGHT, fill=tk.Y)

tk.Label(right, text="Clientes conectados:").pack()
client_listbox = tk.Listbox(right, height=6)
client_listbox.pack(fill=tk.X, padx=5, pady=5)

tk.Label(right, text="Archivos recibidos:").pack()
files_listbox = tk.Listbox(right, width=50)
files_listbox.pack(fill=tk.Y, expand=True, padx=5, pady=5)

btns = tk.Frame(right)
btns.pack(fill=tk.X, pady=5)

tk.Button(btns, text="Anunciar archivo recibido a TODOS", command=announce_selected_file_all).pack(fill=tk.X)
tk.Button(btns, text="Anunciar archivo recibido a Cliente", command=announce_selected_file_user).pack(fill=tk.X)
tk.Button(btns, text="Anunciar archivo LOCAL a Cliente", command=announce_local_file_user).pack(fill=tk.X)
tk.Button(btns, text="Cerrar servidor", command=on_close).pack(fill=tk.X, pady=5)

srv = start_server()
root.after(200, process_gui_queue)
root.protocol("WM_DELETE_WINDOW", on_close)
root.mainloop()
