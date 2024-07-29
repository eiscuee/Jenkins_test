import os
import json
import logging
import logging.config
import time

HAS_SETUP_LOGGING_RUN = False
AUTOMATION_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)


def get_logger(
    name="default",
    default_level=logging.INFO,
):
    setup_logging(default_level, name)
    logger = logging.getLogger(name)
    return logger


def setup_logging(
    default_level=logging.INFO,
    name=None
):
    global HAS_SETUP_LOGGING_RUN
    config = None
    dir_name = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(dir_name, "logging.json")
    log_cfg_env = os.getenv('LOG_CONFIG', None)

    if log_cfg_env is not None:
        path = log_cfg_env
    if os.path.exists(path):
        with open(path, 'r') as FILE:
            config = json.load(FILE)
            _update_logging_dict(config, name)
            logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)

    HAS_SETUP_LOGGING_RUN = True
    return config


def _update_logging_dict(current_dict, name):
    queue = [current_dict]
    while len(queue) > 0:
        head = queue.pop()
        for key, value in head.items():
            if isinstance(value, dict):
                queue.append(value)
            elif isinstance(value, str):
                if "$" in value:
                    value = value.replace(
                        "$AUTOMATION_DIR",
                        AUTOMATION_DIR
                    )
                    if name is None:
                        name = str(time.time())
                    value = value.replace("$LOG_NAME", name)
                    head[key] = value
                    if key in ["filename"]:
                        dir_name = os.path.dirname(value)
                        os.makedirs(dir_name, exist_ok=True)
