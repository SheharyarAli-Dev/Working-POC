import os
from pathlib import Path

def layout(root,package,environ):
    """(assets, state) for code at `package` (the `backend` folder) whose parent is `root`.

    Source tree (root holds requirements.lock.txt and docker/sandbox.Dockerfile): both are `root`, exactly the
    paths a checkout always used. Installed package: assets are read from `backend/_data/` (put there by
    the wheel build) and state is written to a per-user data folder, never into site-packages."""
    if (root/'requirements.lock.txt').is_file() and (root/'docker'/'sandbox.Dockerfile').is_file():return root,root
    if os.name=='nt' and environ.get('LOCALAPPDATA'):base=Path(environ['LOCALAPPDATA'])
    else:base=Path(environ.get('XDG_DATA_HOME') or Path.home()/'.local'/'share')
    return package/'_data',base/'asent'

ROOT=Path(__file__).resolve().parents[1]
ASSETS,STATE=layout(ROOT,Path(__file__).resolve().parent,os.environ)
INSTALLED=ASSETS!=ROOT
DATA=Path(os.environ.get('ASENT_DATA',str(STATE/'runtime'))).resolve()
ADVISORIES=STATE/'advisories'
DEMO=ASSETS/'demo_project'/'InvoiceHub'
VERSION='1.0.0'
MODULES=('CAVR','SATRA','SABLE')
