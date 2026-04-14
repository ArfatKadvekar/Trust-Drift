import argparse
import subprocess
import sys
import os

def run_command(cmd, silent=False):
    """Run command with proper error handling."""
    if not silent:
        print(f"\n[RUNNING] {' '.join(cmd)}\n")
    result = subprocess.run(cmd)
    if result.returncode != 0 and not silent:
        print(f"[ERROR] Command failed with exit code {result.returncode}")
        sys.exit(1)
    return result.returncode


def run_demo(mode):
    """Run a demo simulation."""
    mapping = {
        "normal": "normal_traffic",
        "sudden": "sudden_attack",
        "slow": "low_and_slow"
    }

    if mode not in mapping:
        print("[ERROR] Invalid demo mode. Use: normal | sudden | slow")
        sys.exit(1)

    print(f"\n[DEMO] Starting demo: {mapping[mode]}")
    run_command([sys.executable, "main.py", "--demo", mapping[mode]])


def run_api(port=8000, workers=1):
    """Start FastAPI server."""
    print(f"\n[API] Starting Trust-Drift API server on port {port}...")
    print(f"[DOCS] Available at http://127.0.0.1:{port}/docs")
    print(f"[INFO] Refresh to see updates\n")
    run_command([
        sys.executable,
        "-m",
        "uvicorn",
        "app:app",
        "--reload",
        "--port",
        str(port),
        "--workers",
        str(workers)
    ])


def run_train():
    """Train models from scratch."""
    script_path = "scripts/auto_train_models.py"
    if not os.path.exists(script_path):
        print("❌ Training script not found at scripts/auto_train_models.py")
        sys.exit(1)

    print("\n🤖 Training models from synthetic data...")
    run_command([sys.executable, script_path])


def run_all():
    """Run complete setup."""
    run_train()

    print("\n=== RUNNING DEMO (SUDDEN ATTACK) ===")
    run_demo("sudden")

    print("\n=== STARTING API SERVER ===")
    run_api()


def main():
    """Main entry point with enhanced help."""
    parser = argparse.ArgumentParser(
        description="""
╔═══════════════════════════════════════════════════════════════╗
║   Trust-Drift Zero Trust Network Security Pipeline           ║
║                                                               ║
║   Transparent | Explainable | Production-Ready               ║
╚═══════════════════════════════════════════════════════════════╝
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Demo modes (show transparency):
    python run.py demo normal      # Normal traffic (benign)
    python run.py demo sudden      # Sudden attack spike
    python run.py demo slow        # Gradual degradation

  API server:
    python run.py api              # Start on :8000
    python run.py api --port 9000  # Custom port

  Training:
    python run.py train            # Generate models from synthetic data

  Full setup:
    python run.py all              # Train + demo + start API
        """,
    )

    parser.add_argument(
        "command",
        choices=["demo", "api", "train", "all"],
        help="Command to run"
    )

    parser.add_argument(
        "mode",
        nargs="?",
        help="For 'demo': normal | sudden | slow"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="API port (default: 8000)"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of workers (default: 1)"
    )

    args = parser.parse_args()

    if args.command == "demo":
        if not args.mode:
            print("❌ Please provide demo mode: normal | sudden | slow")
            print("\nExample: python run.py demo sudden")
            sys.exit(1)
        run_demo(args.mode)

    elif args.command == "api":
        run_api(port=args.port, workers=args.workers)

    elif args.command == "train":
        run_train()

    elif args.command == "all":
        run_all()


if __name__ == "__main__":
    main()