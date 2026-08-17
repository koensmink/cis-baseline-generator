class Page:
    def get_text(self, option: str) -> str: ...


class Document:
    page_count: int

    def load_page(self, page_id: int) -> Page: ...


def open(filename: str) -> Document: ...
