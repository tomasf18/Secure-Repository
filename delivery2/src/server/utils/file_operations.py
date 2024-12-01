import json

def read_file(file: str) -> str | None:
    with open(file, "r") as f:
        content = f.read();
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return content
        
def write_file(file: str, content: str):
    with open(file, "wb") as f:
        f.write(content)
        
    

