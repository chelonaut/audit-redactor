"""Importing this package registers every format handler with the pipeline
dispatch table (each submodule's `@register(...)` decorator runs on import).
"""

from audit_redactor.handlers import html_handler, image_handler, json_handler, markdown_handler, pdf_handler

__all__ = ["html_handler", "image_handler", "json_handler", "markdown_handler", "pdf_handler"]
