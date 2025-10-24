
# Add this function to your local_files.py or FileCrawler

import re
from datetime import datetime
import os

def extract_date_from_filename(file_path):
    """
    Extract date from filename pattern: YEAR_filename_YYYYMMDDHHMMSS.html
    """
    filename = os.path.basename(file_path)
    
    # Extract from timestamp at end: _YYYYMMDDHHMMSS.html
    timestamp_match = re.search(r'_(\d{14})\.html$', filename)
    if timestamp_match:
        timestamp_str = timestamp_match.group(1)
        try:
            year = int(timestamp_str[:4])
            month = int(timestamp_str[4:6])
            day = int(timestamp_str[6:8])
            hour = int(timestamp_str[8:10])
            minute = int(timestamp_str[10:12])
            second = int(timestamp_str[12:14])
            return datetime(year, month, day, hour, minute, second)
        except ValueError:
            pass
    
    # Fallback to year from beginning: YYYY_filename
    year_match = re.search(r'^(\d{4})_', filename)
    if year_match:
        year = int(year_match.group(1))
        return datetime(year, 1, 1)
    
    return datetime.now()

# Then modify your Website creation to use:
# timestamp = extract_date_from_filename(file_path)
# instead of datetime.now()
