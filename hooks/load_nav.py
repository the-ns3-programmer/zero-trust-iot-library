# hooks/load_nav.py
import yaml
import os

def on_config(config, **kwargs):
    # Get the directory where mkdocs.yml lives securely from the config object
    base_dir = os.path.dirname(config.config_file_path)
    nav_path = os.path.join(base_dir, 'nav.yml')
    
    if os.path.exists(nav_path):
        with open(nav_path, 'r', encoding='utf-8') as f:
            # Load the external navigation YAML structure
            nav_data = yaml.safe_load(f)
            
            # If nav.yml starts with a top-level 'nav:' key, extract its contents
            if isinstance(nav_data, dict) and 'nav' in nav_data:
                config['nav'] = nav_data['nav']
            else:
                config['nav'] = nav_data
    else:
        print(f"Warning: Navigation file not found at {nav_path}")
        
    return config