import os

def create_folder_and_file(file_name, size_in_mb):
    """
    Creates a new folder with the name of the file, and creates a dummy file inside it 
    with the specified size.
    
    Parameters:
    file_name (str): The name of the file to create (the folder will have the same name).
    size_in_mb (int): The size of the file to create in megabytes.
    """
    folder_name = file_name.split('.')[0]  # Use the file name (without extension) for the folder name
    os.makedirs(folder_name, exist_ok=True)  # Create a new folder with the same name
    
    file_path = os.path.join(folder_name, file_name)  # Path to the file inside the folder
    
    size_in_bytes = size_in_mb * 1024 * 1024  # Convert MB to Bytes
    with open(file_path, 'wb') as f:
        f.write(os.urandom(size_in_bytes))  # Write random data to the file
    
    print(f"{file_name} created in folder {folder_name} with size {size_in_mb} MB")

# Create files in the range 100 MB to 1 GB, each in its own folder
create_folder_and_file("file3_150MB.bin", 150)  # 100-200 MB range
create_folder_and_file("file4_300MB.bin", 300)  # 200-400 MB range
create_folder_and_file("file5_600MB.bin", 600)  # 500-700 MB range
create_folder_and_file("file6_900MB.bin", 900)  # 700 MB - 1 GB range
