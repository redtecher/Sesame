from pydantic import BaseModel


class AnalysisInput(BaseModel):
    web_url: str
    rootfs_path: str
