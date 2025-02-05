import re
from fastapi import HTTPException


async def file_hash_checker(file_hash: str):
    if not re.fullmatch(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", file_hash):
        raise HTTPException(status_code=400, detail="Invalid file hash format. Expected MD5 (32), SHA-1 (40), or SHA-256 (64).")
