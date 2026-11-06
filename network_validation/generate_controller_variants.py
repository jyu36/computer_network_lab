#!/usr/bin/env python3
"""Build controller variants; implementation lives with the controller helpers."""
from controller_variants.Helpers.generate_controller_variants import (
    generate_controller_variants,
    main,
)

__all__ = ["generate_controller_variants", "main"]

if __name__ == "__main__":
    main()
