#!/bin/bash

# LaTeX Build Script for main.tex with BibTeX support
# Silent mode: only outputs errors

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" > /dev/null 2>&1

# Check if main.tex exists
if [ ! -f "main.tex" ]; then
    echo "Error: main.tex not found in current directory" >&2
    exit 1
fi

# Check if xelatex is available
if ! command -v xelatex &> /dev/null; then
    echo "Error: xelatex is not installed or not in PATH" >&2
    exit 1
fi

# Check if bibtex is available
if ! command -v bibtex &> /dev/null; then
    echo "Error: bibtex is not installed or not in PATH" >&2
    exit 1
fi

# First pass xelatex compilation (exit code 1 is expected due to unresolved references)
xelatex -interaction=nonstopmode main.tex > /dev/null 2>&1 || true

# BibTeX compilation
bibtex main > /dev/null 2>&1 || true

# Second pass xelatex compilation
xelatex -interaction=nonstopmode main.tex > /dev/null 2>&1 || true

# Third pass xelatex compilation (finalize references)
xelatex -interaction=nonstopmode main.tex > /dev/null 2>&1 || true

# Check if PDF was generated
if [ -f "main.pdf" ]; then
    # Clean up auxiliary files automatically
    rm -f main.aux main.log main.out main.toc main.lof main.lot main.bbl main.blg
    
    # Open the PDF
    open main.pdf
else
    echo "Error: Build failed! PDF was not generated. Check the log file for errors." >&2
    exit 1
fi
