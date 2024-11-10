from dao.file_dao import files
import json

def download_file(file_handle):
    '''Handles GET requests to /files/<file_handle>'''
    if file_handle not in files:
        return json.dumps(f'File {file_handle} not found'), 404
    
    return json.dumps(files[file_handle]), 200