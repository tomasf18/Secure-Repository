import json

def download_file(file_handle):
    '''Handles GET requests to /files/<file_handle>'''
    org_name, digest = file_handle.split("_")
    