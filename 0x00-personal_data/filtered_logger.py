#!/usr/bin/env python3
"""
Script for masking personal information in log messages.
This version reads data from a CSV file, redacts PII fields,
and logs the sanitized output.
"""

import re
import logging
import os
import csv
from typing import List


class RedactingFormatter(logging.Formatter):
    """
    Formatter to mask specified PII fields in log messages.
    """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initializes the RedactingFormatter with a list of fields to redact.
        """
        self.fields = fields
        super().__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """
        Formats a log record.
        """
        result = super().format(record)
        return filter_datum(
            self.fields,
            self.REDACTION,
            result,
            self.SEPARATOR)


PII_FIELDS = ('name', 'email', 'password', 'ssn', 'phone')


def filter_datum(fields: List[str],
                 redaction: str,
                 message: str,
                 separator: str) -> str:
    """
    Returns regx
    """
    for item in fields:
        message = re.sub(item + '=.*?' + separator, item + '=' +
                         redaction + separator, message)
    return message


def create_user_data_logger() -> logging.Logger:
    """
    configures a logger.
    """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    target_handler = logging.StreamHandler()
    target_handler.setLevel(logging.INFO)

    formatter = RedactingFormatter(PII_FIELDS)
    target_handler.setFormatter(formatter)

    logger.addHandler(target_handler)

    return logger


def get_logger() -> logging.Logger:
    """
    Creates and configures processing.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    return logger


def main() -> None:
    """
    Main data from a CSV file, formats it, and logs it with redacted PII.
    """
    logger = get_logger()

    with open("user_data.csv", newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            fields = '; '.join(
                    [f"{key}={value}" for key, value in row.items()])
            logger.info(fields)


if __name__ == "__main__":
    main()
