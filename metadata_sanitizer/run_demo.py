"""
Demo runner for the Metadata Sanitizer.

Processes sample files from the drone_local_storage directory using
different sanitization modes, and prints formatted results.

Run:
    python -m metadata_sanitizer.run_demo
"""

import json
import os
import sys
import tempfile
import shutil

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from metadata_sanitizer import MetadataSanitizer, SanitizerConfig


def _find_sample_files(base_dir: str) -> list:
    """Find sample files in drone_local_storage for demo."""
    samples = []
    storage_dirs = [
        os.path.join(base_dir, "drone_local_storage"),
        os.path.join(base_dir, "drone_remote_store"),
    ]

    for storage_dir in storage_dirs:
        if not os.path.isdir(storage_dir):
            continue
        for drone_dir in sorted(os.listdir(storage_dir)):
            drone_path = os.path.join(storage_dir, drone_dir)
            if not os.path.isdir(drone_path):
                continue
            for fname in sorted(os.listdir(drone_path)):
                fpath = os.path.join(drone_path, fname)
                if os.path.isfile(fpath):
                    # Guess MIME from extension
                    mime = _guess_mime(fname)
                    samples.append({
                        "artifact_id": f"artifact://demo_{drone_dir}_{fname}",
                        "file_path": fpath,
                        "filename": fname,
                        "mime": mime,
                        "drone_id": drone_dir,
                    })
    return samples


def _guess_mime(filename: str) -> str:
    """Simple extension-to-MIME mapping for demo."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return {
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "tiff": "image/tiff",
        "mp4": "video/mp4",
        "mkv": "video/x-matroska",
        "avi": "video/avi",
        "json": "application/json",
        "csv": "text/csv",
        "txt": "text/plain",
        "zip": "application/zip",
        "tar": "application/x-tar",
        "bin": "application/octet-stream",
        "pdf": "application/pdf",
    }.get(ext, "application/octet-stream")


def _print_header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def _print_result(result: dict, indent: int = 2) -> None:
    """Pretty-print a sanitization result."""
    prefix = " " * indent
    print(f"{prefix}Artifact:  {result['artifact_id']}")
    print(f"{prefix}File:      {result['filename']}")
    print(f"{prefix}Type:      {result['file_type']} ({result['mime_type']})")
    print(f"{prefix}Mode:      {result['mode']}")
    print(f"{prefix}Handler:   {result['handler_used']}")
    print(f"{prefix}Sanitized: {result['sanitized']}")
    print(f"{prefix}Time:      {result['processing_time_ms']:.1f} ms")

    if result.get("skipped"):
        print(f"{prefix}SKIPPED:   {result.get('skip_reason', 'unknown')}")

    if result["changes"]:
        print(f"{prefix}Changes ({len(result['changes'])}):")
        for change in result["changes"]:
            sev = change.get("severity", "info").upper()
            print(f"{prefix}  [{sev:8s}] {change['field']}: "
                  f"{change['action']} ({change['reason']})")

    if result["warnings"]:
        print(f"{prefix}Warnings:")
        for w in result["warnings"]:
            print(f"{prefix}  - {w}")

    if result["errors"]:
        print(f"{prefix}Errors:")
        for e in result["errors"]:
            print(f"{prefix}  ! {e}")

    print()


def demo_audit_mode(sanitizer: MetadataSanitizer, samples: list) -> list:
    """Run all samples in audit-only mode."""
    _print_header("DEMO 1: Audit-Only Mode (no modifications)")
    results = []
    for sample in samples:
        result = sanitizer.sanitize_file(
            artifact_id=sample["artifact_id"],
            file_path=sample["file_path"],
            mime_type=sample["mime"],
            mode_override="audit_only",
        )
        result_dict = result.to_dict()
        _print_result(result_dict)
        results.append(result_dict)
    return results


def demo_selective_mode(sanitizer: MetadataSanitizer, samples: list, work_dir: str) -> list:
    """Run image/text samples in selective mode using temp copies."""
    _print_header("DEMO 2: Selective Mode (remove known-dangerous fields)")
    results = []
    for sample in samples:
        # Work on copies to preserve originals
        temp_path = os.path.join(work_dir, sample["filename"])
        shutil.copy2(sample["file_path"], temp_path)

        result = sanitizer.sanitize_file(
            artifact_id=sample["artifact_id"],
            file_path=temp_path,
            mime_type=sample["mime"],
            threat_score=0.5,  # Medium threat → selective mode
        )
        result_dict = result.to_dict()
        _print_result(result_dict)
        results.append(result_dict)
    return results


def demo_threat_driven(sanitizer: MetadataSanitizer, samples: list, work_dir: str) -> list:
    """Demonstrate threat-score-driven mode selection."""
    _print_header("DEMO 3: Threat-Score-Driven Mode Selection")
    scenarios = [
        ("Low threat (T_S=0.2 → audit_only)", 0.2),
        ("Medium threat (T_S=0.5 → selective)", 0.5),
        ("High threat (T_S=0.85 → strip)", 0.85),
    ]
    results = []
    for label, threat_score in scenarios:
        print(f"  --- {label} ---")
        if not samples:
            print("  No samples found.\n")
            continue
        sample = samples[0]  # Use first sample for demonstration
        temp_path = os.path.join(work_dir, f"ts{threat_score}_{sample['filename']}")
        shutil.copy2(sample["file_path"], temp_path)

        result = sanitizer.sanitize_file(
            artifact_id=sample["artifact_id"],
            file_path=temp_path,
            mime_type=sample["mime"],
            threat_score=threat_score,
        )
        result_dict = result.to_dict()
        _print_result(result_dict)
        results.append(result_dict)
    return results


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    print("Metadata Sanitizer — Demo Runner")
    print(f"Project root: {project_root}")

    # Find sample files
    samples = _find_sample_files(project_root)
    if not samples:
        print("\nNo sample files found in drone_local_storage/.")
        print("Creating synthetic test files for demo...\n")
        samples = _create_synthetic_samples(project_root)

    print(f"Found {len(samples)} sample files\n")
    for s in samples[:10]:
        print(f"  {s['drone_id']}/{s['filename']}  ({s['mime']})")
    if len(samples) > 10:
        print(f"  ... and {len(samples) - 10} more")

    # Initialize sanitizer
    config = SanitizerConfig(
        default_mode="selective",
        preserve_originals=False,  # Don't clutter demo with .orig files
        log_all_metadata=False,    # Reduce log noise in demo
        log_level="WARNING",
    )
    sanitizer = MetadataSanitizer(config)

    # Create temp working directory
    work_dir = tempfile.mkdtemp(prefix="sanitizer_demo_")

    try:
        all_results = []

        # Demo 1: Audit only
        all_results.extend(demo_audit_mode(sanitizer, samples[:5]))

        # Demo 2: Selective
        all_results.extend(demo_selective_mode(sanitizer, samples[:3], work_dir))

        # Demo 3: Threat-driven
        all_results.extend(demo_threat_driven(sanitizer, samples[:2], work_dir))

        # Summary
        _print_header("SUMMARY")
        stats = sanitizer.stats
        print(f"  Total processed:  {stats['total_processed']}")
        print(f"  Total sanitized:  {stats['total_sanitized']}")
        print(f"  Total skipped:    {stats['total_skipped']}")
        print(f"  Total changes:    {stats['total_changes']}")
        print(f"  Total errors:     {stats['total_errors']}")

        # Save results
        output_path = os.path.join(project_root, "sanitizer_demo_output.json")
        with open(output_path, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n  Results saved to: {output_path}")

    finally:
        # Cleanup temp directory
        shutil.rmtree(work_dir, ignore_errors=True)


def _create_synthetic_samples(project_root: str) -> list:
    """Create minimal synthetic files for demo when no real samples exist."""
    demo_dir = os.path.join(project_root, "drone_local_storage", "DEMO-001")
    os.makedirs(demo_dir, exist_ok=True)

    samples = []

    # Text file
    txt_path = os.path.join(demo_dir, "telemetry.json")
    with open(txt_path, "w") as f:
        json.dump({"speed": 12.5, "heading": 145, "battery": 78}, f)
    samples.append({
        "artifact_id": "artifact://demo_telemetry",
        "file_path": txt_path,
        "filename": "telemetry.json",
        "mime": "application/json",
        "drone_id": "DEMO-001",
    })

    # CSV file
    csv_path = os.path.join(demo_dir, "log.csv")
    with open(csv_path, "w") as f:
        f.write("timestamp,lat,lon,alt\n2025-01-01T00:00:00Z,12.97,77.59,120\n")
    samples.append({
        "artifact_id": "artifact://demo_log",
        "file_path": csv_path,
        "filename": "log.csv",
        "mime": "text/csv",
        "drone_id": "DEMO-001",
    })

    return samples


if __name__ == "__main__":
    main()
