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


class MaskingFormatter(logging.Formatter):
    """
    Formatter to mask specified PII fields in log messages.
    """
    MASK = "[REDACTED]"
    LOG_FORMAT = "[APPLICATION] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FIELD_SEPARATOR = ";"

    def __init__(self, sensitive_fields: List[str]):
        """
        Initializes the formatter with fields to mask.
        """
        self.sensitive_fields = sensitive_fields
        super().__init__(self.LOG_FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """
        Applies masking to specified fields in a log record.
        """
        original_message = super().format(record)
        return mask_fields(self.sensitive_fields, self.MASK, original_message, self.FIELD_SEPARATOR)


# Fields that contain PII information
PII_FIELDS = ('name', 'email', 'password', 'ssn', 'phone')


def mask_fields(fields: List[str], mask: str, text: str, separator: str) -> str:
    """
    Masks specified fields within the provided text.
    """
    for field in fields:
        text = re.sub(f"{field}=.*?{separator}", f"{field}={mask}{separator}", text)
    return text


def configure_user_logger() -> logging.Logger:
    """
    Sets up a logger dedicated to handling sensitive user data.
    """
    logger = logging.getLogger('user_info')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)

    formatter = MaskingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    logger.addHandler(stream_handler)

    return logger


def main() -> None:
    """
    Reads data from CSV, applies masking, and logs entries.
    """
    user_logger = configure_user_logger()

    with open("user_data.csv", newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            log_message = '; '.join([f"{key}={value}" for key, value in row.items()])
            user_logger.info(log_message)


if __name__ == "__main__":
    main()
