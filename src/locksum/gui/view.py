from __future__ import annotations

import tkinter as tk
from typing import TYPE_CHECKING

import ttkbootstrap as tb
from ttkbootstrap.tooltip import ToolTip

if TYPE_CHECKING:
    from .controller import Controller


class MainView:
    """Handles the creation and layout of all GUI widgets."""

    def __init__(self, root: tb.Window, controller: Controller | None = None):
        self.root = root
        self.controller: Controller | None = controller
        self._setup_style()

        # Widget placeholders
        self.passcode_entry: tb.Entry | None = None
        self.strength_label: tb.Label | None = None
        self.action_button: tb.Button | None = None
        self.text_input: tk.Text | None = None
        self.hash_var = tk.StringVar()
        self.tree: tb.Treeview | None = None
        self.delete_text_var: tk.StringVar | None = None
        self.save_btn: tb.Button | None = None

        self.status_var = tk.StringVar()
        self.status_bar = tb.Label(
            self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w"
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # ------------------------------------------------------------------
    # Dependency injection helpers
    # ------------------------------------------------------------------

    def set_controller(self, controller: Controller) -> None:  # noqa: D401
        """Link the **already-constructed** controller to this view.

        Separating construction like this avoids the circular dependency dance
        that previously required a temporary ``None`` pass.
        """
        self.controller = controller

    def _setup_style(self) -> None:
        """Configures ttkbootstrap styles and fonts."""
        style = tb.Style()
        default_font = ("Segoe UI", 10)
        heading_font = ("Segoe UI", 12, "bold")
        style.configure("TLabel", font=default_font)
        style.configure("Heading.TLabel", font=heading_font)
        style.configure("TButton", font=default_font, padding=5)
        style.configure("TEntry", font=default_font, padding=5)

    def clear_ui(self) -> None:
        """Removes all widgets from the root window except the status bar."""
        for widget in self.root.winfo_children():
            if widget is not self.status_bar:
                widget.destroy()

    def update_status(self, text: str) -> None:
        """Updates the text in the status bar."""
        self.status_var.set(text)

    def setup_passcode_ui(self) -> None:
        """Creates the initial passcode entry screen."""
        self.clear_ui()
        tb.Label(self.root, text="Locksum Security", style="Heading.TLabel").pack(
            pady=20
        )
        tb.Label(self.root, text="Enter Master Passcode:").pack(pady=5)

        self.passcode_entry = tb.Entry(self.root, show="*", width=35)
        self.passcode_entry.pack(pady=5)
        self.passcode_entry.bind("<KeyRelease>", self.controller.on_passcode_change)
        self.passcode_entry.bind("<Return>", lambda e: self.action_button.invoke())
        self.passcode_entry.focus_set()

        self.strength_label = tb.Label(
            self.root, text="Strength: Too short", style="secondary.TLabel"
        )
        self.strength_label.pack(pady=5)

        self.action_button = tb.Button(self.root, text="Login")
        self.action_button.pack(pady=10)

        # Initial state check
        self.controller.on_passcode_change()

    def setup_main_ui(self) -> None:
        """Creates the main application screen for hashing and storing."""
        self.clear_ui()
        tb.Label(
            self.root, text="Generate & Store Hashes", style="Heading.TLabel"
        ).pack(pady=10)

        self.text_input = tk.Text(self.root, height=5, width=50, font=("Consolas", 10))
        self.text_input.pack(pady=5, padx=20, fill=tk.X)

        frame = tb.Frame(self.root)
        frame.pack(pady=5)
        tb.Button(
            frame,
            text="Generate",
            style="primary.TButton",
            command=self.controller.generate_hash,
        ).pack(side=tk.LEFT, padx=5)
        tb.Button(
            frame,
            text="Clear",
            style="secondary.TButton",
            command=self.controller.clear_input,
        ).pack(side=tk.LEFT, padx=5)

        self._create_hash_display()
        self._create_action_buttons()

    def _create_hash_display(self) -> None:
        """Creates the read-only entry for displaying the generated hash."""
        frame = tb.Frame(self.root)
        frame.pack(pady=10, padx=20, fill=tk.X)
        tb.Label(frame, text="SHA-256 Hash:").pack(side=tk.LEFT, padx=(0, 5))
        hash_entry = tb.Entry(
            frame, textvariable=self.hash_var, state="readonly", font=("Consolas", 9)
        )
        hash_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        copy_btn = tb.Button(
            frame, text="Copy", command=self.controller.copy_to_clipboard
        )
        copy_btn.pack(side=tk.LEFT, padx=(5, 0))
        ToolTip(copy_btn, "Copy hash to clipboard")

    def _create_action_buttons(self) -> None:
        """Creates the main action buttons (Save, View, Logout)."""
        frame = tb.Frame(self.root)
        frame.pack(pady=10)
        self.save_btn = tb.Button(
            frame,
            text="Save",
            style="success.TButton",
            command=self.controller.save_current_hash,
            state="disabled",
        )
        self.save_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(self.save_btn, "Save the generated hash securely")

        view_btn = tb.Button(
            frame,
            text="View Stored",
            style="info.TButton",
            command=self.controller.view_stored_data,
        )
        view_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(view_btn, "View all stored hashes")

        logout_btn = tb.Button(
            frame, text="Logout", style="danger.TButton", command=self.controller.logout
        )
        logout_btn.pack(side=tk.LEFT, padx=5)
        ToolTip(logout_btn, "Logout and clear session")

    def setup_stored_data_ui(self, data: list[tuple[str, str]]) -> None:
        """Creates the screen for viewing all stored text-hash pairs."""
        self.clear_ui()
        tb.Label(self.root, text="Stored Hashes", style="Heading.TLabel").pack(pady=10)

        columns = ("text", "hash")
        self.tree = tb.Treeview(self.root, columns=columns, show="headings", height=10)
        self.tree.heading("text", text="Input Text")
        self.tree.heading("hash", text="SHA-256 Hash")
        self.tree.column("text", width=250)
        self.tree.column("hash", width=350)

        vsb = tb.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(pady=5, padx=20, fill=tk.X)

        for text, hash_val in data:
            self.tree.insert("", tk.END, values=(text, hash_val))

        self.tree.bind("<Double-1>", self.controller.copy_selected_hash_from_tree)
        ToolTip(self.tree, "Double-click a row to copy the hash")

        # ---------------- Delete single entry ----------------
        del_frame = tb.Frame(self.root)
        del_frame.pack(pady=5)
        tb.Label(del_frame, text="Delete Entry by Text:").pack(
            side=tk.LEFT, padx=(0, 5)
        )
        self.delete_text_var = tk.StringVar()
        tb.Entry(
            del_frame,
            textvariable=self.delete_text_var,
            width=30,
        ).pack(side=tk.LEFT, padx=(0, 5))
        tb.Button(
            del_frame,
            text="Delete",
            style="danger.TButton",
            command=self.controller.delete_entry_by_text,
        ).pack(side=tk.LEFT)

        frame = tb.Frame(self.root)
        frame.pack(pady=10)
        tb.Button(frame, text="Back to Main", command=self.setup_main_ui).pack(
            side=tk.LEFT, padx=5
        )
        tb.Button(
            frame,
            text="Wipe All Data",
            style="danger.TButton",
            command=self.controller.confirm_and_wipe_data,
        ).pack(side=tk.LEFT, padx=5)

        self.update_status(f"Viewing {len(data)} stored items.")
