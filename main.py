from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import boto3
import jwt
from datetime import datetime, timedelta
from typing import Optional
import uvicorn


#app = FastAPI()

# AWS Cognito configuration
#USER_POOL_ID = 'your_cognito_user_pool_id'

Client_Id = '' # Despues de crear el cognito el client id lo copiamos de la informacion de app client del cognito creando
Region = '' # La region en la que esta cofigurada el AWS en este caso us-east-1
JWT_Secret = ''

cognito_client = boto3.client('cognito-idp', region_name=Region)


#OAuth2_Scheme for JWT authentication

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models

class User(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    confirmation_code: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str


#Helper functions

def create_jwt_token(username:str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, JWT_Secret, algorithm="HS256")
    return token

def decode_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_Secret, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# API endpoints

app = FastAPI()

@app.post("/signup", response_model=Token)
def signup(user: User):
    try:
        response = cognito_client.sign_up(
            ClientId = Client_Id,
            Username = user.username,
            Password= user.password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': user.email,
                },
            ]
        )
        return response
    except cognito_client.exceptions.UsernameExistsException:
        raise HTTPException(status_code=400, detail="Username already exists")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/confirm", response_model=dict)
def confirm(user: User):
    try:
        response = cognito_client.confirm_sign_up(
            ClientId = Client_Id,
            Username = user.username,
            ConfirmationCode = user.confirmation_code
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/signin", responde_model=Token)
def signin(user: User):
    try:
        response = cognito_client.initiate_auth(
            AuthFlow = 'USER_PASSWORD_AUTH',
            AuthParameters = {
                'Username': user.username,
                'Password': user.password
            },
            ClientId = Client_Id
        )
        token = create_jwt_token(user.username)
        return {"access_token": token, "token_type": "bearer"}
    except cognito_client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/logout", response_model=dict)
def logout(token: str =Depends(oauth2_scheme)):
    try:
        decoded_token = decode_jwt_token(token)
        username = decoded_token['sub']
        response = cognito_client.global_sign_out(
            AccessToken=token
        )
        return {"message": "Successfully logged out"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/demoPage", response_model=dict)
def demo_page(token: str = Depends(oauth2_scheme)):
    decode_jwt_token(token)
    return {"message": "Welcome to the protected route!"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=3000, reload=True)