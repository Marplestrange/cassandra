import os
from pathlib import Path

# Lire le .env
env_path = Path('/root/.env')
if env_path.exists():
    for line in env_path.read_text().splitlines():
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            os.environ[k.strip()] = v.strip()

print('Clé dans os.environ:', os.environ.get('DEEPSEEK_API_KEY', 'NON TROUVEE'))

# Lire aussi directement
with open('/root/.env') as f:
    for line in f:
        if line.startswith('DEEPSEEK_API_KEY='):
            print('Clé directe:', line.strip())
