import sys
import subprocess

def check_dependencies():
    required = {'vcdvcd', 'capstone', 'pandas'}
    installed = {pkg.split('==')[0] for pkg in subprocess.check_output([sys.executable, '-m', 'pip', 'freeze']).decode().split()}
    missing = required - installed
    
    if missing:
        print("\n❌ Missing required libraries:")
        for lib in missing:
            print(f"   - {lib}")
        print("\nPlease run: pip install -r requirements.txt\n")
        sys.exit(1)

if __name__ == "__main__":
    # check_dependencies() # Uncomment this line to enable strict checking
    from src.main import main
    main()