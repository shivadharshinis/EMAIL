import argparse
import codecs
import csv
import os
import sys
import tempfile
from collections import Counter
from email import policy
from email.message import Message
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path

import pandas as pd


PROJECT_DIR = Path(__file__).resolve().parent
DATASET_DIR = PROJECT_DIR / "dataset"
OUTPUT_CSV = DATASET_DIR / "emails.csv"
SOURCES = (("easy_ham", 0), ("spam", 1))
CSV_COLUMNS = ("subject", "body", "label", "source_file")
HTML_BLOCK_TAGS = {
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
    "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
    "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol",
    "p", "pre", "section", "table", "td", "th", "tr", "ul",
}


class ReadableHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_tags: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._ignored_tags.append(tag)
        elif not self._ignored_tags and tag in HTML_BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if not self._ignored_tags and tag in HTML_BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self._ignored_tags:
            if tag == self._ignored_tags[-1]:
                self._ignored_tags.pop()
        elif tag in HTML_BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._ignored_tags:
            self.parts.append(data)

    def text(self) -> str:
        lines = (" ".join(line.split()) for line in "".join(self.parts).splitlines())
        return "\n".join(line for line in lines if line)


def html_to_text(content: str) -> str:
    parser = ReadableHTML()
    parser.feed(content)
    parser.close()
    return parser.text()


def decode_part(part: Message, warnings: list[str]) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        content = part.get_payload()
        return content if isinstance(content, str) else ""

    charset = part.get_content_charset() or "utf-8"
    try:
        codec = codecs.lookup(charset)
    except LookupError:
        warnings.append(
            f"Unsupported charset {charset!r}; decoded as UTF-8 with replacement"
        )
        codec = codecs.lookup("utf-8")

    try:
        return payload.decode(codec.name)
    except UnicodeError:
        warnings.append(
            f"Invalid byte sequence for charset {charset!r}; "
            "decoded with replacement characters"
        )
        return payload.decode(codec.name, errors="replace")


def extract_body(message: Message, warnings: list[str]) -> str:
    plain_part = message.get_body(preferencelist=("plain",))
    if plain_part is not None:
        return decode_part(plain_part, warnings).strip()

    html_part = message.get_body(preferencelist=("html",))
    if html_part is not None:
        return html_to_text(decode_part(html_part, warnings)).strip()

    if message.get_content_maintype() == "text":
        content = decode_part(message, warnings)
        if message.get_content_subtype() == "html":
            return html_to_text(content).strip()
        return content.strip()

    return ""


def format_defects(message: Message) -> list[str]:
    defects: list[str] = []
    for part in message.walk():
        for defect in part.defects:
            defects.append(f"{type(defect).__name__}: {defect}")
    return defects


def read_email(
    path: Path, label: int
) -> tuple[dict[str, object], list[str]]:
    source_file = path.relative_to(PROJECT_DIR).as_posix()
    warnings: list[str] = []
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    subject = str(message.get("Subject", "") or "").strip()
    body = extract_body(message, warnings)
    record = {
        "subject": subject,
        "body": body,
        "label": label,
        "source_file": source_file,
    }
    warnings.extend(format_defects(message))
    return record, warnings


def write_csv(records: list[dict[str, object]], overwrite: bool) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            prefix=".emails-",
            suffix=".tmp",
            dir=DATASET_DIR,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            writer = csv.DictWriter(temporary, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(records)

        if overwrite:
            os.replace(temporary_path, OUTPUT_CSV)
        else:
            os.rename(temporary_path, OUTPUT_CSV)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse SpamAssassin emails and create dataset/emails.csv."
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace dataset/emails.csv if it already exists",
    )
    args = parser.parse_args()

    if not DATASET_DIR.is_dir():
        print(f"Error: dataset directory not found: {DATASET_DIR}", file=sys.stderr)
        return 1
    if OUTPUT_CSV.exists() and not args.overwrite:
        print(
            f"Error: refusing to overwrite existing CSV: {OUTPUT_CSV}\n"
            "Use --overwrite only when you intend to replace it.",
            file=sys.stderr,
        )
        return 1

    folders: dict[str, list[Path]] = {}
    for folder_name, _ in SOURCES:
        folder = DATASET_DIR / folder_name
        if not folder.is_dir():
            print(f"Error: required dataset folder not found: {folder}", file=sys.stderr)
            return 1
        folders[folder_name] = sorted(
            path for path in folder.rglob("*") if path.is_file()
        )

    found_counts = {name: len(paths) for name, paths in folders.items()}
    records: list[dict[str, object]] = []
    failures: list[tuple[str, str]] = []
    parser_warnings: list[tuple[str, str]] = []

    for folder_name, label in SOURCES:
        for path in folders[folder_name]:
            relative_path = path.relative_to(PROJECT_DIR).as_posix()
            try:
                record, defects = read_email(path, label)
                records.append(record)
                parser_warnings.extend((relative_path, defect) for defect in defects)
            except (OSError, UnicodeError, ValueError, LookupError, TypeError) as error:
                failures.append((relative_path, f"{type(error).__name__}: {error}"))

    try:
        write_csv(records, overwrite=args.overwrite)
        frame = pd.read_csv(OUTPUT_CSV, encoding="utf-8", keep_default_na=False)
        if list(frame.columns) != list(CSV_COLUMNS):
            raise ValueError(f"Unexpected CSV columns: {list(frame.columns)!r}")
        if not set(frame["label"].unique()).issubset({0, 1}):
            raise ValueError(f"Unexpected label values: {frame['label'].unique().tolist()!r}")
        if set(frame["label"].unique()) != {0, 1}:
            raise ValueError(f"Expected both labels 0 and 1; found {frame['label'].unique().tolist()!r}")
        if len(frame) != len(records):
            raise ValueError(
                f"CSV record count mismatch: wrote {len(records)}, reopened {len(frame)}."
            )
        source_paths = frame["source_file"].astype(str)
        ham_sources = source_paths.str.startswith("dataset/easy_ham/")
        spam_sources = source_paths.str.startswith("dataset/spam/")
        if not (ham_sources | spam_sources).all():
            raise ValueError("CSV contains a source_file outside the expected dataset folders.")
        if not frame.loc[ham_sources, "label"].eq(0).all():
            raise ValueError("CSV has a non-zero label for an easy_ham source.")
        if not frame.loc[spam_sources, "label"].eq(1).all():
            raise ValueError("CSV has a non-one label for a spam source.")
    except (
        OSError,
        UnicodeError,
        ValueError,
        LookupError,
        TypeError,
        csv.Error,
        pd.errors.ParserError,
        pd.errors.EmptyDataError,
    ) as error:
        print(
            f"Error while writing or verifying {OUTPUT_CSV}: "
            f"{type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    record_counts = Counter(int(label) for label in frame["label"])
    empty_subjects = int(frame["subject"].map(lambda value: not str(value).strip()).sum())
    empty_bodies = int(frame["body"].map(lambda value: not str(value).strip()).sum())
    processed_counts = Counter(int(record["label"]) for record in records)

    print("Processing summary")
    for folder_name, label in SOURCES:
        print(
            f"  {folder_name}: found {found_counts[folder_name]}, "
            f"processed {processed_counts[label]}"
        )
    print(f"  Successfully processed: {len(records)}")
    print(f"  Failed/skipped: {len(failures)}")
    if failures:
        print("  Failure reasons:")
        for filename, reason in failures:
            print(f"    {filename}: {reason}")
    print(f"  Parser warnings/defects (records retained): {len(parser_warnings)}")
    if parser_warnings:
        print("  Parser warning details:")
        for filename, reason in parser_warnings:
            print(f"    {filename}: {reason}")
    print(f"  CSV records per label: label 0={record_counts.get(0, 0)}, label 1={record_counts.get(1, 0)}")
    print(f"  Empty subjects: {empty_subjects}")
    print(f"  Empty bodies: {empty_bodies}")
    print(f"  CSV columns verified: {', '.join(frame.columns)}")
    print(f"  CSV location: {OUTPUT_CSV}")

    print("\nSample CSV rows:")
    sample_indices = frame.head(2).index.tolist()
    spam_samples = frame.index[frame["label"].eq(1)]
    if len(spam_samples):
        sample_indices.append(spam_samples[0])
    for _, row in frame.loc[sample_indices].iterrows():
        body_preview = " ".join(str(row["body"]).split())
        if len(body_preview) > 180:
            body_preview = body_preview[:177] + "..."
        print(
            f"  subject={str(row['subject'])[:100]!r}, "
            f"label={int(row['label'])}, source_file={row['source_file']!r}, "
            f"body={body_preview!r}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
