DOIT_CONFIG = {
    "default_tasks": [""],
    "backend": "sqlite3",
    "action_string_formatting": "new",
    "verbosity": 2,
}


def task_build():
    return {
        "actions": ["python -m nuitka src/tetripin/__main__.py  --standalone"],
    }
