from math import floor
from time import monotonic
from textual.reactive import reactive
import pyotp
from textual import on
from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer
from textual.widgets import Footer, Static, Input, Label, ProgressBar
from textual.widget import Widget
import clipman
from tetripin.exceptions import TetripinError
from tetripin.utils import (
    DATA_DIR,
    build_secret_map_from_toml,
    get_key_from_keyring,
    ensure_secrets_file,
)


clipman.init()


class Header(Widget):
    remaining_time = reactive(30)

    def __init__(self, interval):
        self.interval = interval
        super().__init__()

    def compose(self):
        yield Label("Codes validity: ")
        yield ProgressBar(
            total=self.interval,
            show_eta=False,
            show_percentage=False,
        )

    def watch_remaining_time(self, remaining_time: int) -> None:
        self.query_one(ProgressBar).update(progress=remaining_time)


class Footer(Widget):
    account_filter = reactive("")

    def compose(self):
        yield Input(placeholder="Filter accounts").data_bind(
            value=Footer.account_filter
        )


class CodeLine(Static):
    def __init__(self, account, code, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.account = account
        self.code = code

    def compose(self) -> ComposeResult:
        yield Label(self.account, id="account")
        yield Label(self.code, id="code")

    async def on_click(self, event) -> None:
        clipman.set(self.code)
        self.notify("Copied to clipboard", severity="info", timeout=2)


class Body(Widget):
    codes = reactive({}, recompose=True)

    def compose(self):
        code_lines = [
            CodeLine(account, code, classes=("even" if i % 2 == 0 else "odd"))
            for i, (account, code) in enumerate(self.codes.items())
        ]
        yield ScrollableContainer(*code_lines, id="codes")


class TOTPApp(App):
    CSS_PATH = "codes.tcss"
    BINDINGS = [("d", "toggle_dark", "Toggle dark mode")]

    remaining_time = reactive(30)

    def __init__(self, key=None, secrets_file=None, data_dir=DATA_DIR):
        key = key or get_key_from_keyring()
        if not key:
            self.notify(
                "Your codes are locked, run 'tetripin unlock' first",
                severity="error",
                timeout=10,
            )
            self.secrets_map = {}
        else:
            try:
                secrets_file = secrets_file or ensure_secrets_file(
                    data_dir, secrets_file
                )
                self.secrets_map = build_secret_map_from_toml(key, secrets_file)
            except TetripinError as e:
                self.secrets_map = {}
                self.notify(str(e), severity="error", timeout=10)

        self.interval = 30  # TOTP default time interval

        super().__init__()

    def on_mount(self) -> None:
        self.update_code_lines()
        self.set_interval(1, self.update_timer)
        self.title = f"{self.remaining_time}s"
        self.update_timer()

    def calculate_codes(self, secrets, account_filter):
        secrets = sorted(secrets.items(), key=lambda e: e[0])
        filtered_secrets = [
            (account, seed)
            for account, seed in secrets
            if not account_filter or account_filter in account
        ]
        return {
            account: str(pyotp.TOTP(seed).now()) for account, seed in filtered_secrets
        }

    def calculate_remaining_time(self):
        return floor(self.interval - (monotonic() % self.interval))

    def update_code_lines(self, account_filter=""):
        self.query_one(Body).codes = self.calculate_codes(
            self.secrets_map, account_filter
        )

    def update_timer(self):
        # Calculate the remaining time for the current TOTP code
        self.remaining_time = self.calculate_remaining_time()
        self.title = f"{self.remaining_time}s"
        if self.remaining_time == 0:
            self.update_code_lines()

    @on(Input.Changed)
    def update_code_list_widget(self, event: Input.Changed) -> None:
        self.query_one(Body).codes = self.calculate_codes(self.secrets_map, event.value)

    def compose(self) -> ComposeResult:
        yield Header(interval=self.interval).data_bind(TOTPApp.remaining_time)
        yield Body()
        yield Input(placeholder="Filter accounts", id="footer")

    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark
