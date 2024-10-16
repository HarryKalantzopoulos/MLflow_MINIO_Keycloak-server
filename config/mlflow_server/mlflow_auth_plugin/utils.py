''' Supporting utilities for authentication.'''
import os
from pathlib import Path
import json
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET

TOKENS_DIRPATH = "/home/.config/faith_tokens"
os.makedirs( TOKENS_DIRPATH, exist_ok= True)

def save_tokens(filename: Path, tokens: Dict[str, Any] ) -> None:
    """ Store tokens. """

    filepath = os.path.normpath(os.path.join(TOKENS_DIRPATH, f"{filename}.json"))
    if not filepath.startswith(TOKENS_DIRPATH):
        raise ValueError("Invalid filename")
    with open(filepath, "w", encoding='utf-8') as jfile:

        json.dump(tokens, jfile, indent=4)

    os.chmod(filepath, 0o600)

def load_tokens(filename: Path) -> Optional[Dict[str,Any]]:
    """ Load existing tokens. """

    filepath = os.path.normpath(os.path.join(TOKENS_DIRPATH, f"{filename}.json"))
    if not filepath.startswith(TOKENS_DIRPATH):
        raise ValueError("Invalid filename")
    if not os.path.exists(filepath):

        return None

    with open(filepath, "r", encoding='utf-8') as jfile:
        token = json.load(jfile)

        return token

def xml_writer(filename: Path, session_root:str )->None:
    '''' Stores xml file from minio response. '''

    filepath = os.path.normpath(os.path.join(TOKENS_DIRPATH, f"{filename}.xml"))
    if not filepath.startswith(TOKENS_DIRPATH):
        raise ValueError("Invalid filename")
    session_root = ET.fromstring(session_root)
    tree = ET.ElementTree(session_root)
    tree.write(filepath)

def xml_reader(filename:str)->Optional[ET.Element]:
    ''' Loads xml file if exists. '''
    filepath = os.path.normpath(os.path.join(TOKENS_DIRPATH, f"{filename}.xml"))
    if not filepath.startswith(TOKENS_DIRPATH):
        raise ValueError("Invalid filename")
    if not os.path.exists(filepath):
        return None

    tree = ET.parse(filepath)
    root = tree.getroot()

    return root


def read_file(file_path):
    ''' Read a file.'''
    with open(file_path, 'r') as f:
        file_content = f.read()
    return file_content
