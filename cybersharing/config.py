import json
import os

import typer


def write_config(config: dict):
    config_dir = os.path.expanduser("~/.cybersharing")
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    config_path = os.path.join(config_dir, "config.json")
    with open(config_path, "w") as f:
        f.write(json.dumps(config))


def read_config() -> dict:
    try:
        config = os.path.join(os.path.expanduser("~/.cybersharing"), "config.json")
        with open(config, "r") as f:
            return json.loads(f.read())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        typer.echo("Invalid config file")
        raise typer.Abort()
