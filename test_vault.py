"""Unit tests for the ProductionPasswordVault."""

import pytest
from main import ProductionPasswordVault, PasswordEntry


class TestPasswordGeneration:
    """Tests for the generate_password method."""

    def setup_method(self):
        self.vault = ProductionPasswordVault()

    def test_password_length(self):
        """Generated password should match the requested length."""
        password = self.vault.generate_password(length=32)
        assert len(password) == 32

    def test_password_default_length(self):
        """Default generated password should have length 20."""
        password = self.vault.generate_password()
        assert len(password) == 20

    def test_password_no_ambiguous(self):
        """When avoid_ambiguous=True, password must not contain ambiguous chars."""
        for _ in range(20):  # Run multiple times to reduce random false-negatives
            password = self.vault.generate_password(avoid_ambiguous=True)
            assert not any(c in "0O1lI" for c in password), (
                f"Found ambiguous character in: {password}"
            )

    def test_password_contains_ambiguous_when_allowed(self):
        """When avoid_ambiguous=False, ambiguous chars may appear (statistical check)."""
        found = False
        for _ in range(100):
            password = self.vault.generate_password(avoid_ambiguous=False, length=32)
            if any(c in "0O1lI" for c in password):
                found = True
                break
        assert found, "Expected at least one ambiguous character in 100 attempts"

    def test_password_has_uppercase(self):
        """Generated password should always contain at least one uppercase letter."""
        for _ in range(20):
            password = self.vault.generate_password()
            assert any(c.isupper() for c in password), (
                f"No uppercase letter in: {password}"
            )

    def test_password_has_lowercase(self):
        """Generated password should always contain at least one lowercase letter."""
        for _ in range(20):
            password = self.vault.generate_password()
            assert any(c.islower() for c in password), (
                f"No lowercase letter in: {password}"
            )

    def test_password_has_digit_when_digits_enabled(self):
        """Generated password should always contain a digit when digits=True."""
        for _ in range(20):
            password = self.vault.generate_password(digits=True)
            assert any(c.isdigit() for c in password), (
                f"No digit in: {password}"
            )

    def test_password_no_digit_when_digits_disabled(self):
        """Generated password should contain no digit when digits=False."""
        for _ in range(10):
            password = self.vault.generate_password(digits=False)
            assert not any(c.isdigit() for c in password), (
                f"Unexpected digit in: {password}"
            )

    def test_password_has_symbol_when_symbols_enabled(self):
        """Generated password should contain at least one symbol when symbols=True."""
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/~"
        for _ in range(20):
            password = self.vault.generate_password(symbols=True)
            assert any(c in symbols for c in password), (
                f"No symbol in: {password}"
            )

    def test_password_no_symbol_when_symbols_disabled(self):
        """Generated password should contain no symbols when symbols=False."""
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?/~"
        for _ in range(10):
            password = self.vault.generate_password(symbols=False)
            assert not any(c in symbols for c in password), (
                f"Unexpected symbol in: {password}"
            )


class TestPasswordValidation:
    """Tests for the validate_master_password method."""

    def setup_method(self):
        self.vault = ProductionPasswordVault()

    def test_weak_password_too_short_rejected(self):
        """Password shorter than 14 characters should be rejected."""
        assert self.vault.validate_master_password("Short1!") is False

    def test_weak_password_no_digit_rejected(self):
        """Password without a digit should be rejected."""
        assert self.vault.validate_master_password("NoDigitsPresent!") is False

    def test_weak_password_no_upper_rejected(self):
        """Password without an uppercase letter should be rejected."""
        assert self.vault.validate_master_password("nouppercase123!") is False

    def test_weak_password_no_symbol_rejected(self):
        """Password without a symbol should be rejected."""
        assert self.vault.validate_master_password("NoSymbolsHere123") is False

    def test_strong_password_accepted(self):
        """A password meeting all requirements should be accepted."""
        assert self.vault.validate_master_password("SecurePass123!@#") is True

    def test_strong_password_minimum_length_accepted(self):
        """A 14-character password meeting all requirements should be accepted."""
        assert self.vault.validate_master_password("Abcdefghijk1!a") is True
