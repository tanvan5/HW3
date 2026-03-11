import subprocess
import tempfile
import os
import pytest

BINARY = os.path.join(os.path.dirname(__file__), "password_audit")


def compile_binary():
    """Compile the password_audit binary if it doesn't exist or sources are newer."""
    base = os.path.dirname(__file__)
    src_files = [
        os.path.join(base, "src", "validation.cpp"),
        os.path.join(base, "src", "audit_mode.cpp"),
        os.path.join(base, "src", "main.cpp"),
    ]
    result = subprocess.run(
        ["g++", "-std=c++23", "-I", os.path.join(base, "include")]
        + src_files
        + ["-o", BINARY],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Compilation failed:\n{result.stderr}"


@pytest.fixture(scope="session", autouse=True)
def build():
    compile_binary()


def run_program(args=None, stdin_input=None, timeout=5):
    """Run password_audit with given args and stdin input."""
    cmd = [BINARY] + (args or [])
    proc = subprocess.run(
        cmd,
        input=stdin_input,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc


def _make_file(lines, suffix=".tsv"):
    """Write lines to a temp file with given suffix and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write("\n".join(lines))
    if lines:
        f.write("\n")
    f.close()
    return f.name


class TestPasswordValidation:
    """Test password checking via interactive menu option 1."""

    def _check_password(self, password):
        """Use menu option 1 to check a single password, then quit."""
        stdin = f"1\n{password}\n3\n"
        result = run_program(stdin_input=stdin)
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if line.strip() in ("Valid", "Invalid"):
                return line.strip()
        raise AssertionError(
            f"Expected 'Valid' or 'Invalid' in output, got:\n{result.stdout}"
        )

    def test_valid_password_basic(self):
        assert self._check_password("Abcdefg!") == "Valid"

    def test_valid_password_long(self):
        assert self._check_password("MyP@ssw0rd!XYZ") == "Valid"

    def test_valid_password_special_chars(self):
        assert self._check_password("Hello!@#") == "Valid"

    def test_valid_password_exactly_8_chars(self):
        assert self._check_password("Abcdef!1") == "Valid"

    def test_invalid_too_short(self):
        assert self._check_password("Ab!1") == "Invalid"

    def test_invalid_7_chars(self):
        assert self._check_password("Abcde!1") == "Invalid"

    def test_invalid_no_uppercase(self):
        assert self._check_password("abcdefg!1") == "Invalid"

    def test_invalid_no_special_char(self):
        assert self._check_password("Abcdefg1") == "Invalid"

    def test_invalid_only_lowercase(self):
        assert self._check_password("abcdefgh") == "Invalid"

    def test_invalid_only_uppercase(self):
        assert self._check_password("ABCDEFGH") == "Invalid"

    def test_invalid_empty(self):
        assert self._check_password("") == "Invalid"

    def test_invalid_only_digits(self):
        assert self._check_password("12345678") == "Invalid"

    def test_invalid_short_with_upper_and_special(self):
        assert self._check_password("A!b") == "Invalid"

    def test_valid_all_specials_with_upper(self):
        assert self._check_password("A!@#$%^&") == "Valid"

    def test_invalid_no_upper_all_special(self):
        assert self._check_password("!@#$%^&*") == "Invalid"


class TestCommandLineModeTSV:
    """Test command-line mode with TSV files."""

    def test_all_valid_passwords(self):
        """No entries should be written to output."""
        infile = _make_file(
            ["alice\talice@e.com\tGoodPass!1", "bob\tbob@e.com\tStr0ng!Pw"],
            suffix=".tsv",
        )
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            if os.path.exists(outfile):
                with open(outfile) as f:
                    assert f.read() == ""
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_all_invalid_passwords(self):
        """All entries should be written to output."""
        infile = _make_file(
            ["alice\talice@e.com\tshort", "bob\tbob@e.com\tnouppercase!"],
            suffix=".tsv",
        )
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert "alice\talice@e.com\tshort" == lines[0]
            assert "bob\tbob@e.com\tnouppercase!" == lines[1]
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_mixed_valid_invalid(self):
        """Only invalid entries written to output."""
        infile = _make_file(
            [
                "alice\talice@e.com\tshort",
                "bob\tbob@e.com\tGoodPass!1",
                "charlie\tcharlie@e.com\tnoUPPER1",
                "dave\tdave@e.com\tValid!Pass1",
            ],
            suffix=".tsv",
        )
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert "alice\talice@e.com\tshort" == lines[0]
            assert "charlie\tcharlie@e.com\tnoUPPER1" == lines[1]
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_preserves_email_in_output(self):
        """Email field must be preserved in output."""
        infile = _make_file(["user1\tspecial@domain.org\tbadpw"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                content = f.read().strip()
            parts = content.split("\t")
            assert parts[0] == "user1"
            assert parts[1] == "special@domain.org"
            assert parts[2] == "badpw"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_output_appends_not_overwrites(self):
        """Output file should be opened in append mode."""
        infile = _make_file(["alice\talice@e.com\tbad"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            with open(outfile, "w") as f:
                f.write("existing\texisting@e.com\texisting\n")
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert lines[0] == "existing\texisting@e.com\texisting"
            assert lines[1] == "alice\talice@e.com\tbad"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_empty_input_file(self):
        """Empty input file should produce no output entries."""
        infile = _make_file([], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            if os.path.exists(outfile):
                with open(outfile) as f:
                    assert f.read() == ""
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_error_on_missing_input_file(self):
        """Should print 'Error opening file' for nonexistent input."""
        outfile = tempfile.mktemp(suffix=".tsv")
        result = run_program(args=["/nonexistent/file.tsv", outfile])
        assert "Error opening file" in result.stdout
        if os.path.exists(outfile):
            os.unlink(outfile)

    def test_does_not_enter_menu_in_cli_mode(self):
        """With 2 args, should NOT print the menu and should exit."""
        infile = _make_file(["a\tb\tGoodPass!1"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            result = run_program(args=[infile, outfile])
            assert "1. Check a single password" not in result.stdout
            assert "3. Quit" not in result.stdout
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_tsv_tab_separated_output(self):
        """TSV output must use tab characters as separators."""
        infile = _make_file(["user\tuser@mail.com\tweak"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                line = f.readline().strip()
            assert line.count("\t") == 2
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)


class TestCommandLineModeCSV:
    """Test command-line mode with CSV files."""

    def test_csv_all_invalid(self):
        """All invalid entries from CSV input written to CSV output."""
        infile = _make_file(
            ["alice,alice@e.com,short", "bob,bob@e.com,nouppercase!"],
            suffix=".csv",
        )
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert "alice,alice@e.com,short" == lines[0]
            assert "bob,bob@e.com,nouppercase!" == lines[1]
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_all_valid(self):
        """No entries should be written to output for all-valid CSV."""
        infile = _make_file(
            ["alice,alice@e.com,GoodPass!1", "bob,bob@e.com,Str0ng!Pw"],
            suffix=".csv",
        )
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            if os.path.exists(outfile):
                with open(outfile) as f:
                    assert f.read() == ""
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_mixed_valid_invalid(self):
        """Only invalid entries from CSV written to CSV output."""
        infile = _make_file(
            [
                "alice,alice@e.com,short",
                "bob,bob@e.com,GoodPass!1",
                "charlie,charlie@e.com,noUPPER1",
            ],
            suffix=".csv",
        )
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert "alice,alice@e.com,short" == lines[0]
            assert "charlie,charlie@e.com,noUPPER1" == lines[1]
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_comma_separated_output(self):
        """CSV output must use comma characters as separators, not tabs."""
        infile = _make_file(["user,user@mail.com,weak"], suffix=".csv")
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                line = f.readline().strip()
            assert line.count(",") == 2
            assert "\t" not in line
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_preserves_email(self):
        """Email field must be preserved in CSV output."""
        infile = _make_file(["user1,special@domain.org,badpw"], suffix=".csv")
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                content = f.read().strip()
            parts = content.split(",")
            assert parts[0] == "user1"
            assert parts[1] == "special@domain.org"
            assert parts[2] == "badpw"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_appends_not_overwrites(self):
        """CSV output file should be opened in append mode."""
        infile = _make_file(["alice,alice@e.com,bad"], suffix=".csv")
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            with open(outfile, "w") as f:
                f.write("existing,existing@e.com,existing\n")
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert lines[0] == "existing,existing@e.com,existing"
            assert lines[1] == "alice,alice@e.com,bad"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_empty_input(self):
        """Empty CSV input should produce no output."""
        infile = _make_file([], suffix=".csv")
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            if os.path.exists(outfile):
                with open(outfile) as f:
                    assert f.read() == ""
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_error_on_missing_input(self):
        """Should print 'Error opening file' for nonexistent CSV input."""
        outfile = tempfile.mktemp(suffix=".csv")
        result = run_program(args=["/nonexistent/file.csv", outfile])
        assert "Error opening file" in result.stdout
        if os.path.exists(outfile):
            os.unlink(outfile)


class TestCrossFormat:
    """Test reading one format and writing the other."""

    def test_csv_input_tsv_output(self):
        """Read CSV, write invalid entries as TSV."""
        infile = _make_file(
            ["alice,alice@e.com,short", "bob,bob@e.com,GoodPass!1"],
            suffix=".csv",
        )
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                line = f.read().strip()
            assert line == "alice\talice@e.com\tshort"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_tsv_input_csv_output(self):
        """Read TSV, write invalid entries as CSV."""
        infile = _make_file(
            ["alice\talice@e.com\tshort", "bob\tbob@e.com\tGoodPass!1"],
            suffix=".tsv",
        )
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                line = f.read().strip()
            assert line == "alice,alice@e.com,short"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_csv_input_tsv_output_multiple(self):
        """Multiple invalid entries: CSV in, TSV out."""
        infile = _make_file(
            ["u1,e1,bad1", "u2,e2,bad2", "u3,e3,GoodPass!1"],
            suffix=".csv",
        )
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert lines[0] == "u1\te1\tbad1"
            assert lines[1] == "u2\te2\tbad2"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_tsv_input_csv_output_multiple(self):
        """Multiple invalid entries: TSV in, CSV out."""
        infile = _make_file(
            ["u1\te1\tbad1", "u2\te2\tbad2", "u3\te3\tGoodPass!1"],
            suffix=".tsv",
        )
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert lines[0] == "u1,e1,bad1"
            assert lines[1] == "u2,e2,bad2"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)


class TestInteractiveMenu:
    """Test the interactive menu mode."""

    def test_menu_displays(self):
        """Menu should display 3 options."""
        stdin = "3\n"
        result = run_program(stdin_input=stdin)
        assert "1. Check a single password" in result.stdout
        assert "2. Process a TSV/CSV file" in result.stdout
        assert "3. Quit" in result.stdout

    def test_menu_loops_until_quit(self):
        """Menu should repeat after option 1, then quit on 3."""
        stdin = "1\nAbcdefg!\n1\nshort\n3\n"
        result = run_program(stdin_input=stdin)
        lines = result.stdout.split("\n")
        menu_count = lines.count("1. Check a single password")
        assert menu_count == 3

    def test_menu_option2_processes_tsv_file(self):
        """Option 2 should process a TSV file interactively."""
        infile = _make_file(["alice\talice@e.com\tshort"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            stdin = f"2\n{infile}\n{outfile}\n3\n"
            run_program(stdin_input=stdin)
            with open(outfile) as f:
                content = f.read().strip()
            assert "alice\talice@e.com\tshort" == content
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_menu_option2_processes_csv_file(self):
        """Option 2 should process a CSV file interactively."""
        infile = _make_file(["alice,alice@e.com,short"], suffix=".csv")
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            stdin = f"2\n{infile}\n{outfile}\n3\n"
            run_program(stdin_input=stdin)
            with open(outfile) as f:
                content = f.read().strip()
            assert "alice,alice@e.com,short" == content
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_menu_option2_error_missing_file(self):
        """Option 2 with nonexistent input file should show error and continue."""
        outfile = tempfile.mktemp(suffix=".tsv")
        stdin = f"2\n/nonexistent/file.tsv\n{outfile}\n3\n"
        result = run_program(stdin_input=stdin)
        assert "Error opening file" in result.stdout
        lines = result.stdout.split("\n")
        menu_count = lines.count("1. Check a single password")
        assert menu_count >= 2
        if os.path.exists(outfile):
            os.unlink(outfile)

    def test_quit_exits_cleanly(self):
        """Option 3 should exit with return code 0."""
        result = run_program(stdin_input="3\n")
        assert result.returncode == 0


class TestEdgeCases:
    """Edge case tests for password validation and file processing."""

    def test_password_with_spaces(self):
        """Spaces are non-alphanumeric, so should count as special."""
        stdin = "1\nA bcdefg\n3\n"
        result = run_program(stdin_input=stdin)
        assert "Valid" in result.stdout

    def test_password_with_tab_char(self):
        """Tab is non-alphanumeric."""
        stdin = "1\nA\tbcdefg\n3\n"
        result = run_program(stdin_input=stdin)
        assert "Valid" in result.stdout

    def test_single_entry_valid_tsv(self):
        infile = _make_file(["user\tu@e.com\tGoodPass!1"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            if os.path.exists(outfile):
                with open(outfile) as f:
                    assert f.read() == ""
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_single_entry_invalid_tsv(self):
        infile = _make_file(["user\tu@e.com\tbad"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                content = f.read().strip()
            assert content == "user\tu@e.com\tbad"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_single_entry_valid_csv(self):
        infile = _make_file(["user,u@e.com,GoodPass!1"], suffix=".csv")
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            if os.path.exists(outfile):
                with open(outfile) as f:
                    assert f.read() == ""
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_single_entry_invalid_csv(self):
        infile = _make_file(["user,u@e.com,bad"], suffix=".csv")
        outfile = tempfile.mktemp(suffix=".csv")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                content = f.read().strip()
            assert content == "user,u@e.com,bad"
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_multiple_runs_append(self):
        """Running twice should append, not overwrite."""
        infile = _make_file(["u1\te1\tbad1"], suffix=".tsv")
        outfile = tempfile.mktemp(suffix=".tsv")
        try:
            run_program(args=[infile, outfile])
            infile2 = _make_file(["u2\te2\tbad2"], suffix=".tsv")
            run_program(args=[infile2, outfile])
            with open(outfile) as f:
                lines = f.read().strip().split("\n")
            assert len(lines) == 2
            assert "u1\te1\tbad1" == lines[0]
            assert "u2\te2\tbad2" == lines[1]
            os.unlink(infile2)
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)

    def test_password_exactly_8_all_requirements(self):
        """Exactly 8 chars with all requirements met."""
        stdin = "1\nAbcdef!1\n3\n"
        result = run_program(stdin_input=stdin)
        assert "Valid" in result.stdout

    def test_password_exactly_7_all_requirements(self):
        """7 chars even with all other requirements -> Invalid."""
        stdin = "1\nAbcde!1\n3\n"
        result = run_program(stdin_input=stdin)
        assert "Invalid" in result.stdout

    def test_default_delimiter_for_unknown_extension(self):
        """Non-.csv extension should default to tab delimiter."""
        infile = _make_file(["user\tu@e.com\tbad"], suffix=".txt")
        outfile = tempfile.mktemp(suffix=".txt")
        try:
            run_program(args=[infile, outfile])
            with open(outfile) as f:
                line = f.read().strip()
            assert line == "user\tu@e.com\tbad"
            assert "\t" in line
        finally:
            os.unlink(infile)
            if os.path.exists(outfile):
                os.unlink(outfile)
