import os
import shutil
import requests
import zipfile
from pathlib import Path
from io import BytesIO

def main():
    base_dir = Path(__file__).parent
    data_dir = base_dir / "data" / "falconpy_docs"
    extract_dir = base_dir / "temp_falconpy"
    
    data_dir.mkdir(parents=True, exist_ok=True)
    
    print("Downloading FalconPy repository zip...")
    url = "https://github.com/CrowdStrike/falconpy/archive/refs/heads/main.zip"
    
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=30)
        response.raise_for_status()
    except Exception as e:
        print(f"Failed to download repository: {e}")
        return
        
    print("Extracting zip...")
    with zipfile.ZipFile(BytesIO(response.content)) as zip_ref:
        zip_ref.extractall(extract_dir)
        
    print("Extracting markdown documentation...")
    md_files = list(extract_dir.rglob("*.md"))
    
    copied_count = 0
    for md_file in md_files:
        rel_path = md_file.relative_to(extract_dir)
        safe_name = str(rel_path).replace(os.sep, "_")
        dest_file = data_dir / safe_name
        shutil.copy(md_file, dest_file)
        copied_count += 1
        
    print(f"Successfully copied {copied_count} FalconPy documentation files to {data_dir}.")
    
    print("Cleaning up temporary files...")
    def on_rm_error(func, path, exc_info):
        import stat
        os.chmod(path, stat.S_IWRITE)
        os.unlink(path)
        
    if extract_dir.exists():
        shutil.rmtree(extract_dir, onerror=on_rm_error)
        
    print("Done!")

if __name__ == "__main__":
    main()
