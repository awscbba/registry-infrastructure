import yaml
import sys
import os

workflow_dir = '.codecatalyst/workflows'
for filename in os.listdir(workflow_dir):
    if filename.endswith('.yml'):
        filepath = os.path.join(workflow_dir, filename)
        try:
            with open(filepath, 'r') as f:
                yaml.safe_load(f)
            print(f'✅ {filename} - Valid YAML')
        except yaml.YAMLError as e:
            print(f'❌ {filename} - YAML Error: {e}')
        except Exception as e:
            print(f'⚠️  {filename} - Error: {e}')
