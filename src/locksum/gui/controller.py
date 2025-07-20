from __future__ import annotations

import os
import tkinter as tk
from tkinter import messagebox, simpledialog
from typing import TYPE_CHECKING

from .. import config
from ..logger import logger
from ..model import CryptoModel

if TYPE_CHECKING:
    from .view import MainView


class Controller:
    """
    Orchestrates the application's logic, connecting the view and the model.
    It handles user events, processes data, and updates the UI.
    """

    def __init__(self, model: CryptoModel, view: MainView):
        self.model = model
        self.view = view
        self.is_new_vault = not os.path.exists(config.PASS_HASH_FILE)
        self.stored_data: list[tuple[str, str]] = []
        self.current_data: tuple[str, str] | None = None

    def start(self) -> None:
        """Initializes the application by showing the passcode screen."""
        self.view.update_status("Welcome! Enter your passcode to begin.")
        self.view.setup_passcode_ui()

    def on_passcode_change(self, event: tk.Event | None = None) -> None:
        """Handles live updates as the user types their passcode."""
        passcode = self.view.passcode_entry.get()
        if not passcode:
            self.view.strength_label.config(
                text="Strength: Too short", style="secondary.TLabel"
            )
            if self.is_new_vault:
                self.view.action_button.config(
                    text="Create New Vault", command=self.create_new_vault
                )
            else:
                self.view.action_button.config(text="Login", command=self.attempt_login)
            return

        strength = self.model.check_passcode_strength(passcode)
        score = strength["score"]
        feedback = strength.get("feedback", {}).get("warning", "Good")
        styles = ["danger", "warning", "warning", "info", "success"]
        self.view.strength_label.config(
            text=f"Strength: {feedback}", style=f"{styles[score]}.TLabel"
        )

        if self.is_new_vault:
            self.view.action_button.config(
                text="Create New Vault", command=self.create_new_vault
            )
            self.view.action_button["state"] = "normal" if score >= 2 else "disabled"
        else:
            self.view.action_button.config(text="Login", command=self.attempt_login)

    def create_new_vault(self) -> None:
        """Creates a new encrypted vault with the user's passcode."""
        passcode = self.view.passcode_entry.get()
        pass_buf = bytearray(passcode, "utf-8")
        if self.model.check_passcode_strength(passcode)["score"] < 2:
            messagebox.showerror(
                "Weak Passcode", "Passcode is too weak. Please choose a stronger one."
            )
            return

        self.model.hash_new_passcode(passcode)
        salt = self.model.get_salt()
        self.model.derive_fernet_key(passcode, salt)
        from ..securemem import secure_erase
        secure_erase(pass_buf)
        self.stored_data = []
        self.model.save_encrypted_data(self.stored_data)

        self.view.setup_main_ui()
        self.view.update_status(
            f"Vault created successfully. Stored items: {len(self.stored_data)}"
        )

    def attempt_login(self) -> None:
        """Attempts to log in by verifying the passcode and decrypting data."""
        passcode = self.view.passcode_entry.get()
        pass_buf = bytearray(passcode, "utf-8")
        if not self.model.verify_passcode(passcode):
            messagebox.showerror("Login Failed", "Invalid passcode.")
            self.view.passcode_entry.delete(0, tk.END)
            from ..securemem import secure_erase
            secure_erase(pass_buf)
            return

        try:
            salt = self.model.get_salt()
            alg = self.model.detect_kdf_algorithm()
            self.model.derive_fernet_key(passcode, salt, algorithm=alg)
            self.stored_data = self.model.load_encrypted_data()
            self.view.setup_main_ui()
            self.view.update_status(
                f"Authenticated. Stored items: {len(self.stored_data)}"
            )
        except ValueError as e:
            messagebox.showerror("Login Failed", str(e))
            self.view.passcode_entry.delete(0, tk.END)
            from ..securemem import secure_erase
            secure_erase(pass_buf)

    def generate_hash(self) -> None:
        """Generates a SHA-256 hash from the input text."""
        text = self.view.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to hash.")
            return
        hash_value = self.model.sha256_hash(text)
        self.current_data = (text, hash_value)
        self.view.hash_var.set(hash_value)
        self.view.save_btn["state"] = "normal"
        self.view.update_status("Hash generated. Click Save to store it securely.")

    def clear_input(self) -> None:
        """Clears the text input and hash display."""
        self.view.text_input.delete("1.0", tk.END)
        self.view.hash_var.set("")
        self.current_data = None
        self.view.save_btn["state"] = "disabled"
        self.view.update_status("Input cleared.")

    def save_current_hash(self) -> None:
        """Saves the currently generated text-hash pair."""
        if not self.current_data:
            messagebox.showerror("Error", "No hash has been generated to save.")
            return
        self.stored_data.append(self.current_data)
        self.model.save_encrypted_data(self.stored_data)
        self.clear_input()
        self.view.update_status(f"Hash saved! Total items: {len(self.stored_data)}")

    def copy_to_clipboard(self) -> None:
        """Copies the displayed hash to the clipboard."""
        value = self.view.hash_var.get()
        if not value:
            messagebox.showwarning("Nothing to Copy", "No hash is available to copy.")
            return
        self.view.root.clipboard_clear()
        self.view.root.clipboard_append(value)
        self.view.update_status("Hash copied to clipboard!")

    def copy_selected_hash_from_tree(self, event: tk.Event) -> None:
        """Copies the hash from the selected row in the data view tree."""
        selected_item = self.view.tree.selection()
        if not selected_item:
            return
        item_data = self.view.tree.item(selected_item[0])
        hash_val = item_data["values"][1]
        self.view.root.clipboard_clear()
        self.view.root.clipboard_append(hash_val)
        self.view.update_status(
            f"Copied hash for '{item_data['values'][0]}' to clipboard."
        )

    def view_stored_data(self) -> None:
        """Displays the screen for viewing all stored data."""
        self.view.setup_stored_data_ui(self.stored_data)

    def logout(self) -> None:
        """Logs out, clears sensitive data, and returns to the passcode screen."""
        self.model.clear_runtime_secrets()
        self.stored_data = []
        self.current_data = None
        self.view.setup_passcode_ui()
        self.view.update_status("Logged out successfully.")

    def confirm_and_wipe_data(self) -> None:
        """Shows a confirmation dialog and wipes all data if confirmed."""
        prompt = (
            "Type 'wipe all data' to confirm irreversible deletion of all stored "
            "hashes and security files."
        )
        response = simpledialog.askstring(
            "Confirm Data Wipe", prompt, parent=self.view.root
        )
        if response and response.strip().lower() == "wipe all data":
            logger.warning(
                "User confirmed full data wipe – proceeding to delete all artifacts."
            )
            self.model.wipe_all_data()
            self.logout()
            self.view.update_status("All data has been permanently wiped.")
        else:
            logger.info("Data wipe cancelled by user.")
            self.view.update_status("Data wipe cancelled.")

    # ------------------------------------------------------------------
    # Delete single entry
    # ------------------------------------------------------------------
    def delete_entry_by_text(self) -> None:
        """Delete a single stored entry that matches the provided text."""
        if not self.view.delete_text_var:
            return
        target_text = self.view.delete_text_var.get().strip()
        if not target_text:
            messagebox.showerror("Error", "Please enter the exact text to delete.")
            return

        for idx, (text, _) in enumerate(self.stored_data):
            if text == target_text:
                del self.stored_data[idx]
                logger.info("Deleted entry matching text='%s'", target_text)
                self.model.save_encrypted_data(self.stored_data)
                self.view.setup_stored_data_ui(self.stored_data)
                msg = (
                    f"Deleted entry '{target_text}'. Total stored: "
                    f"{len(self.stored_data)}"
                )
                self.view.update_status(msg)
                return

        logger.info("Delete requested for text='%s' but no match found.", target_text)
        messagebox.showwarning("Not Found", f"No entry found for '{target_text}'.")
