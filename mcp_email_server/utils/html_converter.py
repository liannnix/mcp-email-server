"""
HTML Email to Markdown Converter
Converts complex HTML marketing emails to clean markdown format
"""

import logging
import re
from html import unescape
from urllib.parse import unquote

logger = logging.getLogger(__name__)


def html_to_markdown(html_content: str) -> str:
    """Convert HTML email content to markdown format"""

    if not html_content or not html_content.strip():
        return ""

    # Remove all CSS style blocks
    html_content = re.sub(r"<style[^>]*>.*?</style>", "", html_content, flags=re.DOTALL | re.IGNORECASE)

    # Remove HTML comments
    html_content = re.sub(r"<!--.*?-->", "", html_content, flags=re.DOTALL)

    # Remove script tags
    html_content = re.sub(r"<script[^>]*>.*?</script>", "", html_content, flags=re.DOTALL | re.IGNORECASE)

    # Remove tracking pixels and hidden elements
    html_content = re.sub(r'<img[^>]*width="1"[^>]*height="1"[^>]*>', "", html_content, flags=re.IGNORECASE)
    html_content = re.sub(r"<div[^>]*display:\s*none[^>]*>.*?</div>", "", html_content, flags=re.DOTALL | re.IGNORECASE)

    # Convert headers (h1-h6)
    for i in range(1, 7):
        html_content = re.sub(
            f"<h{i}[^>]*>(.*?)</h{i}>", f"{'#' * i} \\1\n", html_content, flags=re.DOTALL | re.IGNORECASE
        )

    # Convert paragraphs
    html_content = re.sub(r"<p[^>]*>(.*?)</p>", "\\1\n\n", html_content, flags=re.DOTALL | re.IGNORECASE)

    # Convert line breaks
    html_content = re.sub(r"<br\s*/?>", "\n", html_content, flags=re.IGNORECASE)

    # Convert links - extract clean URLs and create markdown links
    def clean_link(match):
        href = match.group(1)
        text = match.group(2)

        # Extract actual URL from tracking redirects
        if "target=" in href:
            # Extract URL from target parameter
            target_match = re.search(r'target=([^&"]*)', href)
            if target_match:
                href = unquote(target_match.group(1))

        # Clean up text
        text = re.sub(r"<[^>]+>", "", text)  # Remove any HTML tags in text
        text = text.strip()

        if text and href:
            return f"[{text}]({href})"
        elif href:
            return f"<{href}>"
        else:
            return text

    html_content = re.sub(
        r'<a[^>]*href="([^"]*)"[^>]*>(.*?)</a>', clean_link, html_content, flags=re.DOTALL | re.IGNORECASE
    )

    # Convert images
    def convert_image(match):
        src = match.group(1)
        alt = match.group(2) if match.group(2) else "Image"
        return f"![{alt}]({src})"

    html_content = re.sub(
        r'<img[^>]*src="([^"]*)"[^>]*alt="([^"]*)"[^>]*>', convert_image, html_content, flags=re.IGNORECASE
    )
    html_content = re.sub(r'<img[^>]*src="([^"]*)"[^>]*>', "![Image](\\1)", html_content, flags=re.IGNORECASE)

    # Convert strong/bold
    html_content = re.sub(
        r"<(?:strong|b)[^>]*>(.*?)</(?:strong|b)>", "**\\1**", html_content, flags=re.DOTALL | re.IGNORECASE
    )

    # Convert emphasis/italic
    html_content = re.sub(r"<(?:em|i)[^>]*>(.*?)</(?:em|i)>", "*\\1*", html_content, flags=re.DOTALL | re.IGNORECASE)

    # Remove all remaining HTML tags
    html_content = re.sub(r"<[^>]+>", "", html_content)

    # Clean up whitespace
    html_content = re.sub(r"\n\s*\n\s*\n", "\n\n", html_content)  # Multiple newlines to double
    html_content = re.sub(r"[ \t]+", " ", html_content)  # Multiple spaces to single
    html_content = re.sub(r"^ +| +$", "", html_content, flags=re.MULTILINE)  # Trim line whitespace

    # Unescape HTML entities
    html_content = unescape(html_content)

    # Clean up special characters
    html_content = html_content.replace("\u00a0", " ")  # Non-breaking space
    html_content = html_content.replace("\u200b", "")  # Zero-width space
    html_content = html_content.replace("\u2014", "—")  # Em dash
    html_content = html_content.replace("\u2013", "-")  # En dash to hyphen

    return html_content.strip()


def extract_plain_text_part(email_msg) -> str:
    """Extract plain text part from email message object"""
    try:
        if email_msg.is_multipart():
            for part in email_msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Handle encoding
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
        return ""
    except Exception as e:
        logger.warning(f"Error extracting plain text part: {e}")
        return ""


def extract_html_part(email_msg) -> str:
    """Extract HTML part from email message object"""
    try:
        if email_msg.is_multipart():
            for part in email_msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        # Handle encoding
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
        return ""
    except Exception as e:
        logger.warning(f"Error extracting HTML part: {e}")
        return ""


def determine_output_format(email_content: str, content_type: str, email_msg, requested_format: str) -> tuple[str, str]:
    """
    Determines the output format and processes content accordingly.
    Returns (processed_content, body_format)
    """

    if requested_format == "html":
        # Always return original content as HTML
        return email_content, "html"

    elif requested_format == "markdown":
        # Handle empty email
        if not email_content or email_content.strip() == "":
            return "", "text"

        # Check content type and process accordingly
        if content_type.startswith("text/html"):
            # HTML → Markdown conversion
            converted = html_to_markdown(email_content)
            return converted, "markdown"

        elif content_type.startswith("text/plain"):
            # Plain text → keep as text format
            return email_content, "text"

        elif "multipart" in content_type and email_msg:
            # Multipart → prefer plain text part
            plain_text_part = extract_plain_text_part(email_msg)
            if plain_text_part and plain_text_part.strip():
                return plain_text_part, "text"
            else:
                # No plain text part - convert HTML part to markdown
                html_part = extract_html_part(email_msg)
                if html_part and html_part.strip():
                    converted = html_to_markdown(html_part)
                    return converted, "markdown"
                else:
                    # No usable parts
                    return "", "text"

        else:
            # Unknown format → return as-is with text format
            return email_content, "text"

    else:
        # Invalid requested format - default to HTML
        logger.warning(f"Invalid format requested: {requested_format}, defaulting to HTML")
        return email_content, "html"
