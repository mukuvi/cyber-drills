import urllib.parse
import re

# Read in chunks if file is huge
with open('Matryoshka.hta', 'r') as f:
    content = f.read()

# Find the largest encoded block (usually the payload)
encoded_pattern = r"unescape\(['\"]([^'\"]+)['\"]\)"
matches = re.findall(encoded_pattern, content, re.DOTALL)

if matches:
    # Take the largest match (main payload)
    encoded = max(matches, key=len)
    
    # Decode repeatedly
    for i in range(20):  
        decoded = urllib.parse.unquote(encoded)
        print(f"Layer {i+1}: {len(decoded)} chars")
        
        # Check for IP
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', decoded)
        if ips:
            print(f"IP Found: {ips[0]}")
            print(f"Flag: flag{{{ips[0]}}}")
            break
        
        # Find next encoded block
        next_match = re.search(r"unescape\(['\"]([^'\"]+)['\"]\)", decoded)
        if next_match:
            encoded = next_match.group(1)
        else:
            # No more nested encoding
            print("Final content (first 500 chars):")
            print(decoded[:500])
            break