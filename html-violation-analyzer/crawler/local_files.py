# crawler/local_files.py
import os

def collect_files(config, country_filter=None):
    """
    Collect HTML files from the input directory.
    
    :param config: Configuration dictionary containing input_dir
    :param country_filter: Optional country code to filter files (e.g., 'UA', 'US')
    :return: List of paths to HTML files
    """
    html_files = []
    root_dir = config.get("input_dir", "./subset_collected_data/snapshot_data")
    
    for root, _, files in os.walk(root_dir):
        # If country filter is specified, check if this directory is for the right country
        if country_filter:
            # Extract country from path
            path_parts = root.replace('\\', '/').split('/')
            country_match = False
            
            for part in path_parts:
                if len(part) == 2 and part.isupper() and part == country_filter:
                    country_match = True
                    break
            
            # Skip if this directory doesn't match the country filter
            if not country_match:
                continue
        
        for file in files:
            if file.endswith(".html"):
                html_files.append(os.path.join(root, file))
    
    # Print summary
    if country_filter:
        print(f"\nFound {len(html_files)} HTML files for country '{country_filter}'")
    else:
        print(f"\nFound {len(html_files)} HTML files in total")
    
    return html_files


def get_available_countries(config):
    """
    Get a list of available country codes in the input directory.
    
    :param config: Configuration dictionary containing input_dir
    :return: Set of country codes found
    """
    root_dir = config.get("input_dir", "./subset_collected_data/snapshot_data")
    
    if not os.path.exists(root_dir):
        return set()
    
    countries = set()
    
    # Look for country directories (2-letter uppercase codes)
    try:
        for item in os.listdir(root_dir):
            item_path = os.path.join(root_dir, item)
            if os.path.isdir(item_path) and len(item) == 2 and item.isupper():
                countries.add(item)
    except Exception:
        return set()
    
    return countries