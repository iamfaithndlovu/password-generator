import tempfile
import unittest
from pathlib import Path

from main import OfflinePasswordVault, generate_password


class PasswordGenerationTests(unittest.TestCase):
    def test_generated_password_has_required_character_groups(self):
        password = generate_password(length=32)

        self.assertGreaterEqual(len(password), 32)
        self.assertTrue(any(ch.islower() for ch in password))
        self.assertTrue(any(ch.isupper() for ch in password))
        self.assertTrue(any(ch.isdigit() for ch in password))
        self.assertTrue(any(not ch.isalnum() for ch in password))

    def test_short_passwords_are_rejected(self):
        with self.assertRaises(Exception):
            generate_password(length=8)


class VaultStorageTests(unittest.TestCase):
    def test_vault_round_trip_is_encrypted_on_disk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vault_path = Path(temp_dir) / "vault.enc"
            master = "CorrectHorse!Battery9"

            vault = OfflinePasswordVault(vault_path)
            vault.setup(master)
            vault.add("email", "faith@example.com", password="SavedSecret!123")
            vault.lock()

            on_disk = vault_path.read_bytes()
            self.assertNotIn(b"SavedSecret!123", on_disk)
            self.assertNotIn(b"faith@example.com", on_disk)

            reopened = OfflinePasswordVault(vault_path)
            reopened.unlock(master)
            entry = reopened.get("email", count_usage=False)

            self.assertEqual(entry.username, "faith@example.com")
            self.assertEqual(entry.password, "SavedSecret!123")


if __name__ == "__main__":
    unittest.main()
