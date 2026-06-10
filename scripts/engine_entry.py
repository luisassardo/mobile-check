"""PyInstaller entry point for the bundled engine (release builds).

Dispatches to the same code the dev path runs, so dev and release are identical:
  <binary>                 -> scan / --detect  (mobilecheck, JSON on stdout)
  <binary> pdf --out P ... -> render a PDF from a payload on stdin

Build with scripts/build-engine.sh.
"""
import sys

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "pdf":
        from engine.report_pdf import main as pdf_main
        sys.exit(pdf_main(sys.argv[2:]))
    from engine.mobilecheck import main as scan_main
    sys.exit(scan_main())
