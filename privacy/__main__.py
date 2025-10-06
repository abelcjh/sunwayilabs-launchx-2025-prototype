"""
CLI entry point for the privacy module.

Usage:
    python -m privacy.consent --help
    python -m privacy.keybroker --help
"""

import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description="Privacy Module CLI")
    parser.add_argument("module", choices=["consent", "keybroker"], 
                       help="Privacy module to run")
    
    args, remaining_args = parser.parse_known_args()
    
    if args.module == "consent":
        from .consent import main as consent_main
        sys.argv = ["privacy.consent"] + remaining_args
        consent_main()
    elif args.module == "keybroker":
        from .keybroker import main as keybroker_main
        sys.argv = ["privacy.keybroker"] + remaining_args
        keybroker_main()

if __name__ == "__main__":
    main()
