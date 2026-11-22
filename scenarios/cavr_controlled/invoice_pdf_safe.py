"""Local, reviewed API-compatible PDF adapter. No network or secret access."""
from io import BytesIO
from pypdf import PdfReader, apply_configuration

def extract_invoice_text(content: bytes) -> str:
    with apply_configuration(jbig2dec_binary=None):
        # Bound to one name: CAVR's guard proof follows `reader = PdfReader(...)`, not an inline `PdfReader(...).pages`.
        reader = PdfReader(BytesIO(content))
        return '\n'.join(page.extract_text() or '' for page in reader.pages)
