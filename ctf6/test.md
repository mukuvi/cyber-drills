# Scan the Python file
yara comprehensive_malware.yar malicious_test.py

# Scan the JavaScript file
yara comprehensive_malware.yar malicious_test.js

# Scan both files recursively in current directory
yara -r comprehensive_malware.yar .

# Verbose output with string matches
yara -s comprehensive_malware.yar malicious_test.py
yara -s comprehensive_malware.yar malicious_test.js