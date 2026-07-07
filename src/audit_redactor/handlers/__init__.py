"""Importing this package registers every format handler with the pipeline
dispatch table (each submodule's `@register(...)` decorator runs on import).
"""

from audit_redactor.handlers import json_handler, markdown_handler, pdf_handler

__all__ = ["json_handler", "markdown_handler", "pdf_handler"]
