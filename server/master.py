import os
from Crypto.Random import get_random_bytes

def generate_master_key(length=32):
    """Generate a master key of the specified byte length."""
    if length != 32:
        raise ValueError("Master key must be 256 bits (32 bytes) for AES-256.")
    master_key = get_random_bytes(length)
    return master_key.hex()

def save_to_bashrc(master_key):
    """Save the master key to .bashrc file in hexadecimal format."""
    bashrc_path = os.path.expanduser("~/.bashrc")  # Change to "~/.zshrc" if using zsh
    export_line = f'\nexport MASTER_KEY="{master_key}"\n'
    
    with open(bashrc_path, "a+") as file:
        file.seek(0)
        lines = file.readlines()
        
        if any("export MASTER_KEY=" in line for line in lines):
            print("MASTER_KEY already set in .bashrc. Updating it now.")
            with open(bashrc_path, "w") as f:
                for line in lines:
                    if "export MASTER_KEY=" in line:
                        f.write(export_line)
                    else:
                        f.write(line)
        else:
            file.write(export_line)
            print("MASTER_KEY added to .bashrc successfully.")

    print(f"Your MASTER_KEY has been saved to {bashrc_path}. Please restart your terminal session to apply.")

if __name__ == "__main__":
    master_key = generate_master_key()
    print(f"Generated MASTER_KEY: {master_key}")  # Optional: Only for debugging, remove in production
    save_to_bashrc(master_key)
