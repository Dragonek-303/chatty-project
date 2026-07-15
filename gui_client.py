#gui_client.py
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import asyncio
import aiohttp
import json
import os
import threading
import socket
from websockets import connect

CONFIG_FILE = "client_config.json"

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}

def save_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)

class App:
    def __init__(self):
        self.server = ""
        self.user_id = ""
        self.config = load_config()
        self.loop = asyncio.new_event_loop()
        self.session = None
        self.ws = None
        self.current_friend = None
        self.friends_ids = []          # surowe ID w kolejności listboxa (który pokazuje aliasy)
        self.displayed_messages = []   # lista wiadomości (dict) w kolejności linii w oknie czatu

        threading.Thread(target=self._run_loop, daemon=True).start()

        # Okno logowania
        self.login_window = tk.Tk()
        self.login_window.title("Komunikator - Logowanie")
        self.login_window.geometry("350x250")

        tk.Label(self.login_window, text="Adres serwera:").pack(pady=(10, 0))
        self.server_entry = tk.Entry(self.login_window, width=40)
        self.server_entry.insert(0, self.config.get("server", "http://127.0.0.1:8000"))
        self.server_entry.pack(pady=5)

        tk.Label(self.login_window, text="E‑mail:").pack()
        self.email_entry = tk.Entry(self.login_window, width=40)
        self.email_entry.pack(pady=5)

        tk.Label(self.login_window, text="Hasło:").pack()
        self.pass_entry = tk.Entry(self.login_window, width=40, show="*")
        self.pass_entry.pack(pady=5)

        btn_frame = tk.Frame(self.login_window)
        btn_frame.pack(pady=10)
        tk.Button(btn_frame, text="Zaloguj", command=self.login, width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Zarejestruj", command=self.register, width=12).pack(side=tk.LEFT, padx=5)

        self.login_window.protocol("WM_DELETE_WINDOW", self.on_close)
        self.login_window.mainloop()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run_async(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    # ---------- Sesja HTTP ----------
    async def _ensure_session(self):
        if self.session is None or self.session.closed:
            # Wymuszamy IPv4, żeby uniknąć opóźnienia przy próbie IPv6 na "localhost".
            connector = aiohttp.TCPConnector(family=socket.AF_INET)
            self.session = aiohttp.ClientSession(connector=connector)

    # ---------- Logowanie / rejestracja ----------
    def _normalize_server(self, value):
        return value.replace("localhost", "127.0.0.1")

    def login(self):
        self.server = self._normalize_server(self.server_entry.get().strip())
        self.config["server"] = self.server
        save_config(self.config)
        email = self.email_entry.get().strip()
        password = self.pass_entry.get().strip()
        if not email or not password:
            messagebox.showerror("Błąd", "Podaj e‑mail i hasło")
            return
        self.run_async(self._login_flow(email, password))

    async def _login_flow(self, email, password):
        await self._ensure_session()
        try:
            async with self.session.post(f"{self.server}/login",
                                         json={"email": email, "password": password}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.user_id = data["user_id"]
                    self.login_window.after(0, self.open_chat)
                else:
                    detail = await resp.json()
                    self.login_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.login_window.after(0, lambda: messagebox.showerror("Błąd połączenia", str(e)))

    def register(self):
        self.server = self._normalize_server(self.server_entry.get().strip())
        self.config["server"] = self.server
        save_config(self.config)
        email = self.email_entry.get().strip()
        password = self.pass_entry.get().strip()
        if not email or not password:
            messagebox.showerror("Błąd", "Podaj e‑mail i hasło")
            return
        self.run_async(self._register_flow(email, password))

    async def _register_flow(self, email, password):
        await self._ensure_session()
        try:
            async with self.session.post(f"{self.server}/register",
                                         json={"email": email, "password": password}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.user_id = data["user_id"]
                    self.login_window.after(0, lambda: messagebox.showinfo("Sukces", f"ID: {self.user_id}"))
                    self.login_window.after(0, self.open_chat)
                else:
                    detail = await resp.json()
                    self.login_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.login_window.after(0, lambda: messagebox.showerror("Błąd połączenia", str(e)))

    # ---------- Okno czatu ----------
    def open_chat(self):
        self.login_window.destroy()
        self.chat_window = tk.Tk()
        self.chat_window.title(f"Komunikator – {self.user_id}")
        self.chat_window.geometry("750x500")

        top_frame = tk.Frame(self.chat_window)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(top_frame, text="Twoje ID:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        self.id_var = tk.StringVar(value=self.user_id)
        id_entry = tk.Entry(top_frame, textvariable=self.id_var, state="readonly", width=32, font=("Consolas", 10))
        id_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(top_frame, text="Kopiuj", command=self.copy_id).pack(side=tk.LEFT)

        # Panel znajomych
        side_frame = tk.Frame(self.chat_window, width=200)
        side_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        header_frame = tk.Frame(side_frame)
        header_frame.pack(fill=tk.X)
        tk.Label(header_frame, text="Znajomi", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        tk.Button(header_frame, text="Odśwież", command=self.refresh_friends).pack(side=tk.RIGHT)

        self.friends_listbox = tk.Listbox(side_frame, width=30, height=15)
        self.friends_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        self.friends_listbox.bind("<<ListboxSelect>>", self.on_friend_select)
        self.friends_listbox.bind("<Button-3>", self.show_friend_menu)   # prawy klawisz (Windows/Linux)
        self.friends_listbox.bind("<Button-2>", self.show_friend_menu)   # prawy klawisz na niektórych Makach

        action_frame = tk.Frame(side_frame)
        action_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Button(action_frame, text="Zaproszenia…", command=self.open_requests_window).pack(fill=tk.X)
        tk.Button(action_frame, text="Zablokowani…", command=self.open_blocked_window).pack(fill=tk.X, pady=(3, 0))

        add_frame = tk.Frame(side_frame)
        add_frame.pack(fill=tk.X, pady=5)
        self.friend_id_entry = tk.Entry(add_frame, width=20)
        self.friend_id_entry.pack(side=tk.LEFT, padx=2)
        tk.Button(add_frame, text="Dodaj", command=self.add_friend).pack(side=tk.LEFT, padx=2)

        # Obszar czatu
        chat_frame = tk.Frame(self.chat_window)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_display = scrolledtext.ScrolledText(chat_frame, state="disabled", wrap=tk.WORD)
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        self.chat_display.bind("<Button-3>", self.show_message_menu)
        self.chat_display.bind("<Button-2>", self.show_message_menu)

        # zaraz nad input_frame, po chat_display
        refresh_btn_frame = tk.Frame(chat_frame)
        refresh_btn_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Button(refresh_btn_frame, text="Odśwież", command=self.refresh_conversation).pack(side=tk.RIGHT, padx=2)

        input_frame = tk.Frame(chat_frame)
        input_frame.pack(fill=tk.X, pady=5)
        self.msg_entry = tk.Entry(input_frame, width=50)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        tk.Button(input_frame, text="Wyślij", command=self.send_message).pack(side=tk.RIGHT, padx=2)

        self.refresh_friends()
        self.connect_websocket()
        self.chat_window.protocol("WM_DELETE_WINDOW", self.on_chat_close)
        self.chat_window.mainloop()

    def copy_id(self):
        self.chat_window.clipboard_clear()
        self.chat_window.clipboard_append(self.user_id)
        messagebox.showinfo("Skopiowano", "ID skopiowane do schowka")

    # ---------- Aliasy (lokalne nazwy znajomych) ----------
    def get_alias(self, friend_id):
        return self.config.get("aliases", {}).get(friend_id, friend_id)

    def set_alias(self, friend_id, alias):
        self.config.setdefault("aliases", {})[friend_id] = alias
        save_config(self.config)

    def clear_alias(self, friend_id):
        # Przy usunięciu znajomego kasujemy nadaną nazwę - po ponownym dodaniu
        # ma wrócić do surowego ID, a nie pamiętać starą nazwę.
        if self.config.get("aliases", {}).pop(friend_id, None) is not None:
            save_config(self.config)

    # ---------- Znajomi ----------
    def refresh_friends(self):
        self.run_async(self._refresh_friends_async())

    async def _refresh_friends_async(self):
        try:
            async with self.session.get(f"{self.server}/friends/{self.user_id}") as resp:
                if resp.status == 200:
                    friends = await resp.json()
                    self.chat_window.after(0, self._update_friends_list, friends)
        except Exception:
            pass

    def _update_friends_list(self, friends):
        self.friends_ids = friends
        self.friends_listbox.delete(0, tk.END)
        for f in friends:
            self.friends_listbox.insert(tk.END, self.get_alias(f))

    def add_friend(self):
        fid = self.friend_id_entry.get().strip()
        if not fid:
            return
        if fid == self.user_id:
            messagebox.showwarning("Uwaga", "Nie możesz dodać samego siebie")
            return
        self.run_async(self._add_friend_async(fid))

    async def _add_friend_async(self, fid):
        try:
            async with self.session.post(f"{self.server}/add_friend",
                                         json={"my_id": self.user_id, "friend_id": fid}) as resp:
                data = await resp.json()
                if resp.status == 200:
                    self.chat_window.after(0, self._add_friend_success, data)
                else:
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", data.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd dodawania", str(e)))

    def _add_friend_success(self, data):
        self.friend_id_entry.delete(0, tk.END)
        self.refresh_friends()
        if data.get("status") == "request sent":
            messagebox.showinfo("Wysłano", "Zaproszenie do znajomych zostało wysłane.\n"
                                            "Zostaniecie znajomymi, gdy druga strona je zaakceptuje.")
        else:
            messagebox.showinfo("OK", "Znajomy dodany")

    def on_friend_select(self, event):
        sel = self.friends_listbox.curselection()
        if sel:
            self.current_friend = self.friends_ids[sel[0]]
            self.load_conversation()

    def show_friend_menu(self, event):
        index = self.friends_listbox.nearest(event.y)
        if index < 0 or index >= len(self.friends_ids):
            return
        self.friends_listbox.selection_clear(0, tk.END)
        self.friends_listbox.selection_set(index)
        fid = self.friends_ids[index]
        menu = tk.Menu(self.chat_window, tearoff=0)
        menu.add_command(label="Zmień nazwę…", command=lambda: self.rename_friend(fid))
        menu.add_separator()
        menu.add_command(label="Usuń ze znajomych", command=lambda: self.remove_friend(fid))
        menu.add_command(label="Usuń i zablokuj", command=lambda: self.block_friend(fid))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def rename_friend(self, fid):
        new_name = simpledialog.askstring(
            "Zmień nazwę",
            "Podaj nazwę wyświetlaną dla tego znajomego:",
            initialvalue=self.get_alias(fid),
            parent=self.chat_window
        )
        if new_name and new_name.strip():
            self.set_alias(fid, new_name.strip())
            self._update_friends_list(self.friends_ids)
            if self.current_friend == fid:
                self.load_conversation()

    def remove_friend(self, fid):
        if messagebox.askyesno("Potwierdź", f"Usunąć {self.get_alias(fid)} ze znajomych?"):
            self.run_async(self._remove_friend_async(fid))

    def block_friend(self, fid):
        if messagebox.askyesno("Potwierdź", f"Usunąć i zablokować {self.get_alias(fid)}?\n"
                                              "Ta osoba nie będzie mogła wysyłać Ci wiadomości ani dodać Cię ponownie."):
            self.run_async(self._block_friend_async(fid))

    async def _remove_friend_async(self, fid):
        try:
            async with self.session.post(f"{self.server}/remove_friend",
                                         json={"my_id": self.user_id, "friend_id": fid}) as resp:
                if resp.status == 200:
                    self.chat_window.after(0, self._friend_removed_locally, fid)
                else:
                    detail = await resp.json()
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd", str(e)))

    async def _block_friend_async(self, fid):
        try:
            async with self.session.post(f"{self.server}/block_user",
                                         json={"my_id": self.user_id, "target_id": fid}) as resp:
                if resp.status == 200:
                    self.chat_window.after(0, self._friend_removed_locally, fid)
                else:
                    detail = await resp.json()
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd", str(e)))

    def _friend_removed_locally(self, fid):
        self.clear_alias(fid)   # POPRAWKA: reset nazwy - przy ponownym dodaniu wróci do ID
        if self.current_friend == fid:
            self.current_friend = None
            self.chat_display.config(state="normal")
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state="disabled")
            self.displayed_messages = []
        self.refresh_friends()

    # ---------- Zaproszenia do znajomych ----------
    def open_requests_window(self):
        win = tk.Toplevel(self.chat_window)
        win.title("Zaproszenia do znajomych")
        win.geometry("320x350")
        tk.Label(win, text="Oczekujące zaproszenia", font=("Arial", 10, "bold")).pack(pady=5)
        listbox = tk.Listbox(win, width=40, height=12)
        listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        request_ids = []

        def refresh_window():
            self.run_async(self._load_requests_async(listbox, request_ids))

        def accept_selected():
            sel = listbox.curselection()
            if not sel:
                return
            fid = request_ids[sel[0]]
            self.run_async(self._accept_request_async(fid, refresh_window))

        def decline_selected():
            sel = listbox.curselection()
            if not sel:
                return
            fid = request_ids[sel[0]]
            self.run_async(self._decline_request_async(fid, refresh_window))

        btn_frame = tk.Frame(win)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="Akceptuj", command=accept_selected).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Odrzuć", command=decline_selected).pack(side=tk.LEFT, padx=5)
        tk.Button(win, text="Odśwież", command=refresh_window).pack(pady=(0, 5))

        refresh_window()

    async def _load_requests_async(self, listbox, request_ids):
        try:
            async with self.session.get(f"{self.server}/friend_requests/{self.user_id}") as resp:
                if resp.status == 200:
                    requests = await resp.json()
                    self.chat_window.after(0, self._fill_requests_listbox, listbox, request_ids, requests)
        except Exception:
            pass

    def _fill_requests_listbox(self, listbox, request_ids, requests):
        request_ids.clear()
        request_ids.extend(requests)
        listbox.delete(0, tk.END)
        for fid in requests:
            listbox.insert(tk.END, self.get_alias(fid))

    async def _accept_request_async(self, fid, on_done):
        try:
            async with self.session.post(f"{self.server}/accept_friend",
                                         json={"my_id": self.user_id, "friend_id": fid}) as resp:
                if resp.status == 200:
                    self.chat_window.after(0, on_done)
                    self.chat_window.after(0, self.refresh_friends)
                else:
                    detail = await resp.json()
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd", str(e)))

    async def _decline_request_async(self, fid, on_done):
        try:
            async with self.session.post(f"{self.server}/decline_friend",
                                         json={"my_id": self.user_id, "friend_id": fid}) as resp:
                if resp.status == 200:
                    self.chat_window.after(0, on_done)
                else:
                    detail = await resp.json()
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd", str(e)))

    # ---------- Okno zablokowanych ----------
    def open_blocked_window(self):
        win = tk.Toplevel(self.chat_window)
        win.title("Zablokowani")
        win.geometry("300x350")
        tk.Label(win, text="Zablokowani użytkownicy", font=("Arial", 10, "bold")).pack(pady=5)
        listbox = tk.Listbox(win, width=40, height=15)
        listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        blocked_ids = []

        def unblock_selected():
            sel = listbox.curselection()
            if not sel:
                return
            fid = blocked_ids[sel[0]]
            self.run_async(self._unblock_async(fid, refresh_window))

        tk.Button(win, text="Odblokuj zaznaczonego", command=unblock_selected).pack(pady=5)

        def refresh_window():
            self.run_async(self._load_blocked_async(listbox, blocked_ids))

        refresh_window()

    async def _load_blocked_async(self, listbox, blocked_ids):
        try:
            async with self.session.get(f"{self.server}/blocked/{self.user_id}") as resp:
                if resp.status == 200:
                    blocked = await resp.json()
                    self.chat_window.after(0, self._fill_blocked_listbox, listbox, blocked_ids, blocked)
        except Exception:
            pass

    def _fill_blocked_listbox(self, listbox, blocked_ids, blocked):
        blocked_ids.clear()
        blocked_ids.extend(blocked)
        listbox.delete(0, tk.END)
        for fid in blocked:
            listbox.insert(tk.END, self.get_alias(fid))

    async def _unblock_async(self, fid, on_done):
        try:
            async with self.session.post(f"{self.server}/unblock_user",
                                         json={"my_id": self.user_id, "target_id": fid}) as resp:
                if resp.status == 200:
                    self.chat_window.after(0, on_done)
                else:
                    detail = await resp.json()
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd", str(e)))

    # ---------- Konwersacja ----------
    def load_conversation(self):
        if self.current_friend:
            self.run_async(self._load_conversation_async())

    async def _load_conversation_async(self):
        try:
            async with self.session.get(
                f"{self.server}/conversation/{self.user_id}/{self.current_friend}?limit=10000000000000") as resp:
                if resp.status == 200:
                    msgs = await resp.json()
                    self.chat_window.after(0, self._display_conversation, msgs)
        except Exception:
            pass

    def _format_line(self, msg):
        sender = "Ja" if msg["from"] == self.user_id else self.get_alias(self.current_friend)
        text = "[wiadomość usunięta]" if msg.get("deleted") else msg["content"].replace("\n", " ")
        return f"[{msg['time']}] {sender}: {text}\n"

    def _display_conversation(self, msgs):
        self.chat_display.config(state="normal")
        self.chat_display.delete(1.0, tk.END)
        self.displayed_messages = []
        for msg in msgs:
            self.chat_display.insert(tk.END, self._format_line(msg))
            self.displayed_messages.append(msg)
        self.chat_display.config(state="disabled")
        self.chat_display.see(tk.END)

    def _append_message(self, msg):
        if self._msg_exists(msg.get("id")):
            return
        self.chat_display.config(state="normal")
        self.chat_display.insert(tk.END, self._format_line(msg))
        self.chat_display.config(state="disabled")
        self.chat_display.see(tk.END)
        self.displayed_messages.append(msg)

    def _msg_exists(self, msg_id):
        """Sprawdza, czy wiadomość o danym ID już istnieje w displayed_messages."""
        return any(m.get("id") == msg_id for m in self.displayed_messages)

    def show_message_menu(self, event):
        index_str = self.chat_display.index(f"@{event.x},{event.y}")
        line = int(index_str.split(".")[0]) - 1
        if line < 0 or line >= len(self.displayed_messages):
            return
        msg = self.displayed_messages[line]
        if msg.get("deleted"):
            return  # nic do usunięcia
        menu = tk.Menu(self.chat_window, tearoff=0)
        menu.add_command(label="Usuń u siebie", command=lambda: self.delete_message(msg, "me"))
        if msg["from"] == self.user_id:
            menu.add_command(label="Usuń u wszystkich", command=lambda: self.delete_message(msg, "everyone"))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def delete_message(self, msg, mode):
        question = "Usunąć tę wiadomość tylko u siebie?" if mode == "me" else \
                   "Usunąć tę wiadomość u wszystkich? Tej operacji nie da się cofnąć."
        if messagebox.askyesno("Potwierdź", question):
            self.run_async(self._delete_message_async(msg["id"], mode))

    async def _delete_message_async(self, message_id, mode):
        try:
            async with self.session.post(f"{self.server}/delete_message", json={
                "user_id": self.user_id,
                "message_id": message_id,
                "mode": mode
            }) as resp:
                if resp.status == 200:
                    if mode == "me":
                        # Usuwamy lokalnie tylko ten jeden wiersz
                        self.chat_window.after(0, self._remove_message_locally, message_id)
                    else:
                        # Dla "everyone" wiadomość zmienia treść – przeładuj całość
                        self.chat_window.after(0, self.load_conversation)
                else:
                    detail = await resp.json()
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd", str(e)))

    def _remove_message_locally(self, message_id):
        """Usuwa wiersz z widoku czatu odpowiadający podanemu ID wiadomości."""
        for i, msg in enumerate(self.displayed_messages):
            if msg.get("id") == message_id:
                del self.displayed_messages[i]
                self.chat_display.config(state="normal")
                # Tkinter numeruje linie od 1
                self.chat_display.delete(float(i + 1), float(i + 2))
                self.chat_display.config(state="disabled")
                break

    def send_message(self):
        if not self.current_friend:
            messagebox.showwarning("Brak znajomego", "Wybierz znajomego z listy")
            return
        msg = self.msg_entry.get().strip()
        if not msg:
            return
        self.msg_entry.delete(0, tk.END)
        self.run_async(self._send_message_async(msg))

    async def _send_message_async(self, msg):
        try:
            async with self.session.post(f"{self.server}/send", json={
                "sender_id": self.user_id,
                "receiver_id": self.current_friend,
                "content": msg
            }) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.chat_window.after(0, self._append_message, data["message"])
                else:
                    detail = await resp.json()
                    self.chat_window.after(0, lambda: messagebox.showerror("Błąd", detail.get("detail", "")))
        except Exception as e:
            self.chat_window.after(0, lambda: messagebox.showerror("Błąd wysyłania", str(e)))

    def refresh_conversation(self):
        """Wymusza pełne przeładowanie aktualnej konwersacji (jak w starej wersji)."""
        if self.current_friend:
            self.run_async(self._load_conversation_async())

    # ---------- WebSocket ----------
    async def websocket_listener(self):
        uri = self.server.replace("http", "ws") + f"/ws/{self.user_id}"
        while True:
            try:
                async with connect(uri) as websocket:
                    self.ws = websocket
                    async for message in websocket:
                        data = json.loads(message)
                        if data["type"] == "new_message":
                            msg = data["data"]
                            # Pokaż tylko jeśli dotyczy aktywnego rozmówcy
                            if self.current_friend and (
                                (msg["from"] == self.current_friend and msg["to"] == self.user_id) or
                                (msg["from"] == self.user_id and msg["to"] == self.current_friend)
                            ):
                                # Jeżeli wiadomość już wyświetlona (np. dodana przy wysyłaniu) – pomiń
                                self.chat_window.after(0, self._append_message, msg)
                        elif data["type"] == "friend_added":
                            self.chat_window.after(0, self.refresh_friends)
                        elif data["type"] == "friend_removed":
                            fid = data["data"]["friend_id"]
                            self.chat_window.after(0, self._friend_removed_locally, fid)
                        elif data["type"] == "friend_request":
                            from_id = data["data"]["from_id"]
                            self.chat_window.after(0, lambda: messagebox.showinfo(
                                "Nowe zaproszenie",
                                f"{self.get_alias(from_id)} chce dodać Cię do znajomych.\n"
                                f"Otwórz 'Zaproszenia…', aby odpowiedzieć."))
                        elif data["type"] == "message_deleted":
                            if self.current_friend:
                                self.chat_window.after(0, self.load_conversation)
            except Exception as e:
                print("WebSocket error, reconnecting in 3s:", e)
                await asyncio.sleep(3)

    def connect_websocket(self):
        self.run_async(self.websocket_listener())

    # ---------- Zamknięcie ----------
    async def _close(self):
        if self.session:
            await self.session.close()

    def on_chat_close(self):
        if self.ws:
            self.run_async(self.ws.close())
        self.run_async(self._close())
        self.chat_window.destroy()
        self.loop.call_soon_threadsafe(self.loop.stop)

    def on_close(self):
        self.run_async(self._close())
        self.login_window.destroy()
        self.loop.call_soon_threadsafe(self.loop.stop)

if __name__ == "__main__":
    App()
