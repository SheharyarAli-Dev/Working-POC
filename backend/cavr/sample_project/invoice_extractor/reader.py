"""
Sample Project: Invoice PDF Extractor.
Extracts invoice text and document metadata from PDF invoices.

This is the project the CAVR dashboard verifies requests for. pypdf's optional JBIG2 decoder
runs an external program, so every reader is created and used inside
`apply_configuration(jbig2dec_binary=None)`, which turns that decoder off.
"""
from pypdf import PdfReader, apply_configuration


class InvoiceReader:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def extract_text(self) -> str:
        with apply_configuration(jbig2dec_binary=None):
            reader = PdfReader(self.filepath)
            text_parts = []
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text_parts.append(extracted)
        return "\n".join(text_parts)

    def parse_metadata(self) -> dict:
        with apply_configuration(jbig2dec_binary=None):
            reader = PdfReader(self.filepath)
            metadata = dict(reader.metadata or {})
        return metadata
