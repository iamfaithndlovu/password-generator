from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from main import DEFAULT_VAULT_PATH, OfflinePasswordVault, VaultError, generate_password


class PasswordAssistantApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Offline Password Assistant")
        self.root.geometry("860x620")
        self.root.minsize(760, 560)

        self.vault = OfflinePasswordVault(DEFAULT_VAULT_PATH)
        self.suggested_password = tk.StringVar()
        self.status_text = tk.StringVar(value="Unlock or create your offline vault.")
        self.service_text = tk.StringVar()
        self.username_text = tk.StringVar()
        self.length_value = tk.IntVar(value=24)
        self.use_symbols = tk.BooleanVar(value=True)
        self.avoid_ambiguous = tk.BooleanVar(value=True)
        self.always_on_top = tk.BooleanVar(value=False)
        self.auto_suggest = tk.BooleanVar(value=True)
        self.clipboard_value: str | None = None

        self._build_styles()
        self._build_layout()
        self._show_locked_view()
        self._wire_suggestion_events()

    def _build_styles(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#f7f7f4")
        style.configure("Panel.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        style.configure("TLabel", background="#f7f7f4", foreground="#1f2933")
        style.configure("Panel.TLabel", background="#ffffff", foreground="#1f2933")
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), background="#f7f7f4")
        style.configure("Muted.TLabel", foreground="#667085", background="#f7f7f4")
        style.configure("Password.TEntry", font=("Consolas", 15))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"))

    def _build_layout(self) -> None:
        self.shell = ttk.Frame(self.root, padding=18)
        self.shell.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(self.shell)
        header.pack(fill=tk.X, pady=(0, 14))
        ttk.Label(header, text="Offline Password Assistant", style="Title.TLabel").pack(anchor=tk.W)
        ttk.Label(
            header,
            text="Suggest, copy, and save strong passwords locally in your encrypted vault.",
            style="Muted.TLabel",
        ).pack(anchor=tk.W, pady=(2, 0))

        self.locked_frame = ttk.Frame(self.shell, style="Panel.TFrame", padding=18)
        self.app_frame = ttk.Frame(self.shell)

        status = ttk.Label(self.shell, textvariable=self.status_text, style="Muted.TLabel")
        status.pack(fill=tk.X, pady=(12, 0))

    def _show_locked_view(self) -> None:
        self.app_frame.pack_forget()
        for child in self.locked_frame.winfo_children():
            child.destroy()

        self.locked_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            self.locked_frame,
            text=f"Vault: {self.vault.vault_file}",
            style="Panel.TLabel",
            wraplength=720,
        ).pack(anchor=tk.W, pady=(0, 14))

        form = ttk.Frame(self.locked_frame, style="Panel.TFrame")
        form.pack(fill=tk.X)
        ttk.Label(form, text="Master password", style="Panel.TLabel").grid(
            row=0, column=0, sticky=tk.W, pady=(0, 8)
        )
        self.master_entry = ttk.Entry(form, show="*", width=42)
        self.master_entry.grid(row=1, column=0, sticky=tk.EW, padx=(0, 10))
        self.master_entry.focus_set()
        form.columnconfigure(0, weight=1)

        buttons = ttk.Frame(form, style="Panel.TFrame")
        buttons.grid(row=1, column=1, sticky=tk.E)
        ttk.Button(buttons, text="Unlock", command=self._unlock, style="Primary.TButton").pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(buttons, text="Create Vault", command=self._create_vault).pack(side=tk.LEFT)
        self.master_entry.bind("<Return>", lambda _event: self._unlock())

        ttk.Label(
            self.locked_frame,
            text="No passwords are shown until the vault is unlocked. New vaults use AES-256-GCM encryption and stay on this computer.",
            style="Panel.TLabel",
            wraplength=720,
        ).pack(anchor=tk.W, pady=(16, 0))

    def _show_app_view(self) -> None:
        self.locked_frame.pack_forget()
        for child in self.app_frame.winfo_children():
            child.destroy()

        self.app_frame.pack(fill=tk.BOTH, expand=True)
        controls = ttk.Frame(self.app_frame)
        controls.pack(fill=tk.X, pady=(0, 12))
        ttk.Checkbutton(
            controls,
            text="Always on top",
            variable=self.always_on_top,
            command=self._toggle_always_on_top,
        ).pack(side=tk.LEFT)
        ttk.Checkbutton(
            controls,
            text="Auto-suggest while typing",
            variable=self.auto_suggest,
        ).pack(side=tk.LEFT, padx=(18, 0))
        ttk.Button(controls, text="Lock", command=self._lock).pack(side=tk.RIGHT)

        main = ttk.PanedWindow(self.app_frame, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True)

        generator = ttk.Frame(main, style="Panel.TFrame", padding=16)
        vault_panel = ttk.Frame(main, style="Panel.TFrame", padding=16)
        main.add(generator, weight=3)
        main.add(vault_panel, weight=2)

        ttk.Label(generator, text="Service", style="Panel.TLabel").grid(row=0, column=0, sticky=tk.W)
        service_entry = ttk.Entry(generator, textvariable=self.service_text)
        service_entry.grid(row=1, column=0, columnspan=3, sticky=tk.EW, pady=(4, 12))

        ttk.Label(generator, text="Username", style="Panel.TLabel").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(generator, textvariable=self.username_text).grid(
            row=3, column=0, columnspan=3, sticky=tk.EW, pady=(4, 12)
        )

        ttk.Label(generator, text="Length", style="Panel.TLabel").grid(row=4, column=0, sticky=tk.W)
        ttk.Spinbox(
            generator,
            from_=12,
            to=80,
            textvariable=self.length_value,
            width=8,
            command=self._maybe_generate,
        ).grid(row=5, column=0, sticky=tk.W, pady=(4, 12))
        ttk.Checkbutton(
            generator,
            text="Symbols",
            variable=self.use_symbols,
            command=self._maybe_generate,
        ).grid(row=5, column=1, sticky=tk.W, padx=(10, 0), pady=(4, 12))
        ttk.Checkbutton(
            generator,
            text="Avoid ambiguous",
            variable=self.avoid_ambiguous,
            command=self._maybe_generate,
        ).grid(row=5, column=2, sticky=tk.W, padx=(10, 0), pady=(4, 12))

        ttk.Label(generator, text="Suggested password", style="Panel.TLabel").grid(
            row=6, column=0, sticky=tk.W
        )
        ttk.Entry(
            generator,
            textvariable=self.suggested_password,
            style="Password.TEntry",
            state="readonly",
        ).grid(row=7, column=0, columnspan=3, sticky=tk.EW, pady=(4, 12))

        buttons = ttk.Frame(generator, style="Panel.TFrame")
        buttons.grid(row=8, column=0, columnspan=3, sticky=tk.EW)
        ttk.Button(buttons, text="Generate", command=self._generate_now).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Copy", command=self._copy_suggestion).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(buttons, text="Save", command=self._save_suggestion, style="Primary.TButton").pack(
            side=tk.LEFT, padx=(8, 0)
        )

        ttk.Label(
            generator,
            text="Tip: keep this window on top and type a service name whenever you need a fresh password. The suggestion is not stored until you click Save.",
            style="Panel.TLabel",
            wraplength=430,
        ).grid(row=9, column=0, columnspan=3, sticky=tk.W, pady=(18, 0))
        generator.columnconfigure(0, weight=1)

        ttk.Label(vault_panel, text="Saved passwords", style="Panel.TLabel").pack(anchor=tk.W)
        self.saved_list = tk.Listbox(vault_panel, height=14, activestyle="dotbox")
        self.saved_list.pack(fill=tk.BOTH, expand=True, pady=(8, 10))
        self.saved_list.bind("<<ListboxSelect>>", self._load_selected_entry)

        saved_buttons = ttk.Frame(vault_panel, style="Panel.TFrame")
        saved_buttons.pack(fill=tk.X)
        ttk.Button(saved_buttons, text="Copy", command=self._copy_selected_saved).pack(side=tk.LEFT)
        ttk.Button(saved_buttons, text="Reveal", command=self._reveal_selected_saved).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(saved_buttons, text="Delete", command=self._delete_selected_saved).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        self._generate_now()
        self._refresh_saved_list()
        service_entry.focus_set()
        self.status_text.set("Vault unlocked. Suggestions are ready.")

    def _wire_suggestion_events(self) -> None:
        self.service_text.trace_add("write", lambda *_args: self._maybe_generate())
        self.length_value.trace_add("write", lambda *_args: self._maybe_generate())

    def _unlock(self) -> None:
        try:
            self.vault.unlock(self.master_entry.get())
        except VaultError as exc:
            messagebox.showerror("Unlock failed", str(exc))
            return
        self.master_entry.delete(0, tk.END)
        self._show_app_view()

    def _create_vault(self) -> None:
        if self.vault.exists and not messagebox.askyesno(
            "Vault exists", "A vault already exists. Replace it with a new empty vault?"
        ):
            return
        try:
            self.vault.setup(self.master_entry.get(), force=True)
        except VaultError as exc:
            messagebox.showerror("Create vault failed", str(exc))
            return
        self.master_entry.delete(0, tk.END)
        self._show_app_view()

    def _lock(self) -> None:
        self.vault.lock()
        self.suggested_password.set("")
        self.status_text.set("Vault locked.")
        self._show_locked_view()

    def _toggle_always_on_top(self) -> None:
        self.root.attributes("-topmost", self.always_on_top.get())

    def _maybe_generate(self) -> None:
        if self.auto_suggest.get() and hasattr(self, "app_frame"):
            self.root.after_idle(self._generate_now)

    def _generate_now(self) -> None:
        try:
            password = generate_password(
                length=int(self.length_value.get()),
                symbols=self.use_symbols.get(),
                avoid_ambiguous=self.avoid_ambiguous.get(),
            )
        except (tk.TclError, VaultError) as exc:
            self.status_text.set(str(exc))
            return
        self.suggested_password.set(password)
        self.status_text.set("Fresh strong password suggested.")

    def _save_suggestion(self) -> None:
        service = self.service_text.get().strip()
        username = self.username_text.get().strip() or service
        password = self.suggested_password.get()
        if not service:
            messagebox.showwarning("Service required", "Enter a service name before saving.")
            return
        if not password:
            self._generate_now()
            password = self.suggested_password.get()

        try:
            self.vault.add(service, username, password=password)
        except VaultError as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self._refresh_saved_list()
        self.status_text.set(f"Saved password for {service} in the offline vault.")

    def _refresh_saved_list(self) -> None:
        self.saved_list.delete(0, tk.END)
        for entry in self.vault.list_entries():
            self.saved_list.insert(tk.END, f"{entry.service}  |  {entry.username}")

    def _selected_service(self) -> str | None:
        selected = self.saved_list.curselection()
        if not selected:
            messagebox.showinfo("Choose a saved password", "Select a saved item first.")
            return None
        row = self.saved_list.get(selected[0])
        return row.split("  |  ", 1)[0]

    def _load_selected_entry(self, _event: tk.Event | None = None) -> None:
        service = self._selected_service_silent()
        if not service:
            return
        try:
            entry = self.vault.get(service, count_usage=False)
        except VaultError:
            return
        self.service_text.set(entry.service)
        self.username_text.set(entry.username)

    def _selected_service_silent(self) -> str | None:
        selected = self.saved_list.curselection()
        if not selected:
            return None
        row = self.saved_list.get(selected[0])
        return row.split("  |  ", 1)[0]

    def _copy_suggestion(self) -> None:
        password = self.suggested_password.get()
        if not password:
            self._generate_now()
            password = self.suggested_password.get()
        self._copy_to_clipboard(password, "Suggested password copied. Clipboard clears in 30 seconds.")

    def _copy_selected_saved(self) -> None:
        service = self._selected_service()
        if not service:
            return
        try:
            entry = self.vault.get(service)
        except VaultError as exc:
            messagebox.showerror("Copy failed", str(exc))
            return
        self._copy_to_clipboard(entry.password, f"Password for {service} copied. Clipboard clears in 30 seconds.")

    def _reveal_selected_saved(self) -> None:
        service = self._selected_service()
        if not service:
            return
        try:
            entry = self.vault.get(service, count_usage=False)
        except VaultError as exc:
            messagebox.showerror("Reveal failed", str(exc))
            return
        messagebox.showinfo(f"Password for {service}", entry.password)

    def _delete_selected_saved(self) -> None:
        service = self._selected_service()
        if not service:
            return
        if not messagebox.askyesno("Delete password", f"Delete saved password for {service}?"):
            return
        try:
            self.vault.delete(service)
        except VaultError as exc:
            messagebox.showerror("Delete failed", str(exc))
            return
        self._refresh_saved_list()
        self.status_text.set(f"Deleted saved password for {service}.")

    def _copy_to_clipboard(self, value: str, status: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.clipboard_value = value
        self.status_text.set(status)
        self.root.after(30_000, self._clear_clipboard_if_unchanged)

    def _clear_clipboard_if_unchanged(self) -> None:
        try:
            if self.root.clipboard_get() == self.clipboard_value:
                self.root.clipboard_clear()
                self.status_text.set("Clipboard cleared.")
        except tk.TclError:
            pass
        finally:
            self.clipboard_value = None


def main() -> None:
    root = tk.Tk()
    PasswordAssistantApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
