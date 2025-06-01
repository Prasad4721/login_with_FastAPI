from pydantic import BaseModel

class Item(BaseModel):
    name: str
    email: str
    password: str

class ItemCreate(Item):
    pass

class ItemUpdate(Item):
    id: int