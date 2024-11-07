
from fastapi import FastAPI, Depends, HTTPException, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import jwt


SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5  # Very short expiration time

app = FastAPI()

fake_users_db = {
    "admin": {"username": "admin", "password": "secret"},
    "user1": {"username": "user1", "password": "password1"},
    "user2": {"username": "user2", "password": "password2"},
}
 
# Function to create JWT token
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.now()+ expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    print(user, "token url")
    if not user or user["password"] != form_data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": form_data.username})

    # Set the token in a cookie with a session expiration (browser will remove cookie when closed)
    response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60, expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60)

    return {"message": "Logged in successfully"}

@app.get("/protected")
async def protected_route(request: Request, response: Response):
    access_token = request.cookies.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Token validation and user verification logic
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        print(username)
        user = fake_users_db.get(username)
        print(user, 'protected')
        if not user:
            response.delete_cookie("access_token")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"message": f"Hello, {username}, you are authenticated!"}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.post("/logout")
async def logout(response: Response):
    # Remove the cookie by setting an expiration in the past
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}