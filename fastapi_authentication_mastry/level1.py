

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

@app.post("/token", include_in_schema=False)
async def token(form_data: OAuth2PasswordRequestForm = Depends()):
    print(f"Form data: {form_data.__dict__}")
    # Authenticate the user, return a token (typically JWT)
    return {"access_token": "some-jwt-token", "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    # Verify token, extract user data
    print(token)    
    return {"username": "user1"}
