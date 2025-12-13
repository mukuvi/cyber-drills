import requests
import zipfile
import os

# Download the zip file
url = "https://hubchallenges.s3.eu-west-1.amazonaws.com/reverse/Whites+Only.zip"
response = requests.get(url)

# Save the zip file
with open("Whites_Only.zip", "wb") as f:
    f.write(response.content)

# Extract the zip file
with zipfile.ZipFile("Whites_Only.zip", 'r') as zip_ref:
    zip_ref.extractall("whites_only_challenge")

# List extracted files
extracted_files = os.listdir("whites_only_challenge")
print("Extracted files:", extracted_files)

# Read the PGN file
pgn_path = os.path.join("whites_only_challenge", "0001.pgn")
with open(pgn_path, 'r') as f:
    pgn_content = f.read()

print("\nPGN Content:")
print(pgn_content)