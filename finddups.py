import os
import hashlib
import sqlite3


db_name = "file_hashes.db"

def create_database(db_name):
    """Creates a SQLite database with two tables: hashes and file_paths."""

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Create the hashes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hashes (
            hash TEXT PRIMARY KEY
        )
    ''')

    # Create the file_paths table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_paths (
            file_path TEXT PRIMARY KEY,
            hash TEXT,
            FOREIGN KEY (hash) REFERENCES hashes (hash)
        )
    ''')

    conn.commit()
    conn.close()

def insert_hash_and_path(db_name, hash_value, file_path):
    """Inserts a hash and file path into the database."""

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    try:
        # Insert the hash if it doesn't exist
        cursor.execute("INSERT OR IGNORE INTO hashes (hash) VALUES (?)", (hash_value,))

        # Insert the file path and associate it with the hash
        cursor.execute("INSERT OR IGNORE INTO file_paths (file_path, hash) VALUES (?, ?)", (file_path, hash_value))

        conn.commit()
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()

    finally:
        conn.close()

def get_file_paths_for_hash(db_name, hash_value):
    """Retrieves all file paths associated with a given hash."""

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("SELECT file_path FROM file_paths WHERE hash = ?", (hash_value,))
    file_paths = [row[0] for row in cursor.fetchall()]

    conn.close()
    return file_paths

def get_hashes(db_name):
    """Retrieves all stored hashes."""

    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    cursor.execute("SELECT hash FROM hashes")
    hashes = [row[0] for row in cursor.fetchall()]

    conn.close()
    return hashes


def find_duplicate_files(directory, file_extensions):
    """
    Finds duplicate files of specified types within a given directory.

    Args:
        directory (str): The path to the directory to search.
        file_extensions (tuple): A tuple of file extensions to search for (e.g., ('.docx', '.xlsx')).

    Returns:
        dict: A dictionary where keys are file hashes and values are lists of file paths with that hash.
    """

    file_hashes = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            if not filename.lower().endswith(file_extensions): # Check if the file matches the desired extensions
                file_path = os.path.join(root, filename)
                try:
                    file_hash = hash_file(file_path)
                    if file_hash:
                        if file_hash in file_hashes:
                            file_hashes[file_hash].append(file_path)
                        else:
                            file_hashes[file_hash] = [file_path]
                except OSError as e:
                    print(f"Error processing {file_path}: {e}")

    duplicates = {hash_val: paths for hash_val, paths in file_hashes.items() if len(paths) > 1}
    return duplicates

def hash_file(file_path, block_size=65536):
    """
    Calculates the SHA-256 hash of a file.

    Args:
        file_path (str): The path to the file.
        block_size (int): The size of the blocks to read from the file.

    Returns:
        str: The hexadecimal representation of the file's SHA-256 hash, or None if an error occurs.
    """
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(block_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return None

def print_duplicates(duplicates):
    """
    Prints the duplicate files found.

    Args:
        duplicates (dict): A dictionary of duplicate files (as returned by find_duplicate_files).
    """
    if not duplicates:
        print("No duplicate files found.")
        return

    for hash_val, paths in duplicates.items():
        print(f"Duplicate files (hash: {hash_val}):")
        for path in paths:
            insert_hash_and_path(db_name, hash_val, path)
            print(f"  - {path}")
        print("-" * 20)

if __name__ == "__main__":
    directory_to_search = input("Enter the directory to search for duplicates: ")
    #file_types = ('.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.rtf', '.png', '.jpg', '.gif') # extensions to process.
    file_types = ('.py', '.pyc', '.plist') # extensions to exclude

    if not os.path.isdir(directory_to_search):
        print(f"Error: '{directory_to_search}' is not a valid directory.")
    else:
        create_database(db_name)
        duplicate_files = find_duplicate_files(directory_to_search, file_types)
        print_duplicates(duplicate_files)